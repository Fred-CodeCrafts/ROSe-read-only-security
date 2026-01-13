"""
Risk Assessor - Evaluates and prioritizes security risks.

This module assesses the business impact and risk levels of identified threats,
providing prioritization and risk scoring for security incidents.
"""

import logging
from typing import List, Dict, Any
from datetime import datetime

from aws_bedrock_athena_ai.reasoning_engine.models import (
    Threat, RiskAssessment, RiskLevel, ThreatSeverity
)


logger = logging.getLogger(__name__)


class RiskAssessor:
    """
    Assesses and prioritizes security risks based on threat analysis.
    """
    
    def __init__(self):
        """Initialize the risk assessor."""
        self.severity_weights = {
            ThreatSeverity.CRITICAL: 10.0,
            ThreatSeverity.HIGH: 7.5,
            ThreatSeverity.MEDIUM: 5.0,
            ThreatSeverity.LOW: 2.5,
            ThreatSeverity.INFO: 1.0
        }
        
        self.business_impact_multipliers = {
            'data_breach': 2.0,
            'system_compromise': 1.8,
            'service_disruption': 1.5,
            'compliance_violation': 1.7,
            'reputation_damage': 1.6,
            'financial_loss': 1.9
        }
        
        # Business impact scoring matrix
        self.business_impact_scores = {
            'revenue_impact': {
                'critical': 10,  # >$1M potential loss
                'high': 7,       # $100K-$1M potential loss
                'medium': 5,     # $10K-$100K potential loss
                'low': 2         # <$10K potential loss
            },
            'operational_impact': {
                'critical': 10,  # Complete service outage
                'high': 7,       # Major service degradation
                'medium': 5,     # Minor service impact
                'low': 2         # No service impact
            },
            'compliance_impact': {
                'critical': 9,   # Regulatory violations, fines
                'high': 6,       # Audit findings
                'medium': 4,     # Policy violations
                'low': 1         # Minor compliance gaps
            },
            'reputation_impact': {
                'critical': 8,   # Public disclosure, media coverage
                'high': 6,       # Customer complaints
                'medium': 4,     # Internal reputation damage
                'low': 1         # No reputation impact
            }
        }
    
    def calculate_business_impact_score(self, threat: Threat) -> Dict[str, Any]:
        """
        Calculate detailed business impact score for a threat.
        
        Args:
            threat: Threat to assess
            
        Returns:
            Dictionary containing business impact analysis
        """
        try:
            # Determine impact categories based on threat type and description
            revenue_impact = self._assess_revenue_impact(threat)
            operational_impact = self._assess_operational_impact(threat)
            compliance_impact = self._assess_compliance_impact(threat)
            reputation_impact = self._assess_reputation_impact(threat)
            
            # Calculate overall business impact score
            total_score = (
                self.business_impact_scores['revenue_impact'][revenue_impact] +
                self.business_impact_scores['operational_impact'][operational_impact] +
                self.business_impact_scores['compliance_impact'][compliance_impact] +
                self.business_impact_scores['reputation_impact'][reputation_impact]
            )
            
            # Normalize to 0-10 scale
            normalized_score = min(total_score / 4.0, 10.0)
            
            # Ensure critical threats have minimum business impact of 5.0
            if threat.severity == ThreatSeverity.CRITICAL:
                normalized_score = max(normalized_score, 5.0)
            elif threat.severity == ThreatSeverity.HIGH:
                normalized_score = max(normalized_score, 3.0)
            
            return {
                'overall_score': round(normalized_score, 2),
                'revenue_impact': revenue_impact,
                'operational_impact': operational_impact,
                'compliance_impact': compliance_impact,
                'reputation_impact': reputation_impact,
                'business_justification': self._generate_business_justification(threat, {
                    'revenue': revenue_impact,
                    'operational': operational_impact,
                    'compliance': compliance_impact,
                    'reputation': reputation_impact
                })
            }
            
        except Exception as e:
            logger.error(f"Error calculating business impact: {str(e)}")
            return {
                'overall_score': 5.0,
                'revenue_impact': 'medium',
                'operational_impact': 'medium',
                'compliance_impact': 'medium',
                'reputation_impact': 'medium',
                'business_justification': 'Unable to assess business impact due to analysis error'
            }
    
    def generate_actionable_response_guidance(self, threats: List[Threat]) -> Dict[str, Any]:
        """
        Generate actionable response guidance for identified threats.
        
        Args:
            threats: List of threats to generate guidance for
            
        Returns:
            Dictionary containing response guidance and priorities
        """
        try:
            # Prioritize threats by business impact
            prioritized_threats = self.prioritize_threats(threats)
            
            # Generate immediate actions for critical threats
            immediate_actions = []
            short_term_actions = []
            long_term_actions = []
            
            for threat in prioritized_threats:
                business_impact = self.calculate_business_impact_score(threat)
                
                if threat.severity == ThreatSeverity.CRITICAL:
                    immediate_actions.extend(self._generate_immediate_actions(threat, business_impact))
                elif threat.severity == ThreatSeverity.HIGH:
                    short_term_actions.extend(self._generate_short_term_actions(threat, business_impact))
                else:
                    long_term_actions.extend(self._generate_long_term_actions(threat, business_impact))
            
            # Generate resource allocation guidance
            resource_guidance = self._generate_resource_allocation_guidance(prioritized_threats)
            
            # Generate escalation matrix
            escalation_matrix = self._generate_escalation_matrix(prioritized_threats)
            
            return {
                'immediate_actions': immediate_actions[:5],  # Top 5 immediate actions
                'short_term_actions': short_term_actions[:10],  # Top 10 short-term actions
                'long_term_actions': long_term_actions[:15],  # Top 15 long-term actions
                'resource_guidance': resource_guidance,
                'escalation_matrix': escalation_matrix,
                'overall_priority': self._determine_overall_priority(prioritized_threats)
            }
            
        except Exception as e:
            logger.error(f"Error generating response guidance: {str(e)}")
            return {
                'immediate_actions': [],
                'short_term_actions': [],
                'long_term_actions': [],
                'resource_guidance': 'Unable to generate guidance due to analysis error',
                'escalation_matrix': {},
                'overall_priority': 'medium'
            }
    
    def assess_risk_levels(self, threats: List[Threat]) -> RiskAssessment:
        """
        Assess overall risk level based on identified threats.
        
        Args:
            threats: List of identified threats
            
        Returns:
            Comprehensive risk assessment
        """
        try:
            logger.info(f"Assessing risk levels for {len(threats)} threats")
            
            # Count threats by severity
            threat_counts = self._count_threats_by_severity(threats)
            
            # Calculate overall risk score
            risk_score = self._calculate_overall_risk_score(threats)
            
            # Determine risk level
            risk_level = self._determine_risk_level(risk_score)
            
            # Identify key risk factors
            risk_factors = self._identify_risk_factors(threats)
            
            # Calculate mitigation coverage
            mitigation_coverage = self._calculate_mitigation_coverage(threats)
            
            # Determine trend (simplified - would need historical data)
            trend = self._determine_risk_trend(threats)
            
            assessment = RiskAssessment(
                overall_risk_score=risk_score,
                risk_level=risk_level,
                critical_threats=threat_counts['critical'],
                high_threats=threat_counts['high'],
                medium_threats=threat_counts['medium'],
                low_threats=threat_counts['low'],
                risk_factors=risk_factors,
                mitigation_coverage=mitigation_coverage,
                trend=trend
            )
            
            logger.info(f"Risk assessment complete: {risk_level.value} risk level, score {risk_score:.2f}")
            return assessment
            
        except Exception as e:
            logger.error(f"Error assessing risk levels: {str(e)}")
            # Return default assessment
            return RiskAssessment(
                overall_risk_score=5.0,
                risk_level=RiskLevel.MEDIUM,
                critical_threats=0,
                high_threats=0,
                medium_threats=len(threats),
                low_threats=0,
                risk_factors=["Assessment error occurred"],
                mitigation_coverage=0.0,
                trend="unknown"
            )
    
    def prioritize_threats(self, threats: List[Threat]) -> List[Threat]:
        """
        Prioritize threats by business impact and risk level.
        
        Args:
            threats: List of threats to prioritize
            
        Returns:
            Threats sorted by priority (highest first)
        """
        try:
            # Calculate priority score for each threat
            threat_priorities = []
            for threat in threats:
                priority_score = self._calculate_threat_priority(threat)
                threat_priorities.append((threat, priority_score))
            
            # Sort by priority score (descending)
            threat_priorities.sort(key=lambda x: x[1], reverse=True)
            
            # Return sorted threats
            prioritized_threats = [threat for threat, _ in threat_priorities]
            
            logger.info(f"Prioritized {len(prioritized_threats)} threats")
            return prioritized_threats
            
        except Exception as e:
            logger.error(f"Error prioritizing threats: {str(e)}")
            return threats
    
    def _count_threats_by_severity(self, threats: List[Threat]) -> Dict[str, int]:
        """Count threats by severity level."""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for threat in threats:
            if threat.severity == ThreatSeverity.CRITICAL:
                counts['critical'] += 1
            elif threat.severity == ThreatSeverity.HIGH:
                counts['high'] += 1
            elif threat.severity == ThreatSeverity.MEDIUM:
                counts['medium'] += 1
            elif threat.severity == ThreatSeverity.LOW:
                counts['low'] += 1
        
        return counts
    
    def _calculate_overall_risk_score(self, threats: List[Threat]) -> float:
        """Calculate overall risk score based on threats."""
        if not threats:
            return 0.0
        
        total_score = 0.0
        for threat in threats:
            # Base score from severity
            base_score = self.severity_weights.get(threat.severity, 5.0)
            
            # Adjust by confidence
            confidence_adjusted = base_score * threat.confidence
            
            # Adjust by number of affected systems
            system_multiplier = min(1.0 + (len(threat.affected_systems) * 0.1), 2.0)
            
            threat_score = confidence_adjusted * system_multiplier
            total_score += threat_score
        
        # Normalize to 0-10 scale, but ensure critical threats push score higher
        critical_count = sum(1 for t in threats if t.severity == ThreatSeverity.CRITICAL)
        high_count = sum(1 for t in threats if t.severity == ThreatSeverity.HIGH)
        
        # Base normalized score
        max_possible_score = len(threats) * 10.0 * 2.0  # max severity * max multiplier
        normalized_score = (total_score / max_possible_score) * 10.0 if max_possible_score > 0 else 0.0
        
        # Boost score for critical threats to ensure it meets expectations
        if critical_count > 0:
            # Ensure at least 5.0 for any critical threat presence
            normalized_score = max(normalized_score, 5.0 + (critical_count * 1.0))
        elif high_count > 0:
            # Ensure reasonable score for high threats
            normalized_score = max(normalized_score, 3.0 + (high_count * 0.5))
        
        return round(min(normalized_score, 10.0), 2)
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from numeric score."""
        if risk_score >= 8.0:
            return RiskLevel.CRITICAL
        elif risk_score >= 6.0:
            return RiskLevel.HIGH
        elif risk_score >= 3.0:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _identify_risk_factors(self, threats: List[Threat]) -> List[str]:
        """Identify key risk factors from threats."""
        risk_factors = []
        
        # Check for critical threats
        critical_count = sum(1 for t in threats if t.severity == ThreatSeverity.CRITICAL)
        if critical_count > 0:
            risk_factors.append(f"{critical_count} critical threat(s) identified")
        
        # Check for widespread impact
        all_systems = set()
        for threat in threats:
            all_systems.update(threat.affected_systems)
        if len(all_systems) > 10:
            risk_factors.append(f"Threats affecting {len(all_systems)} systems")
        
        # Check for specific threat types
        threat_types = [t.threat_type.value for t in threats]
        if 'data_breach' in threat_types:
            risk_factors.append("Potential data breach detected")
        if 'intrusion' in threat_types:
            risk_factors.append("System intrusion detected")
        if 'malware' in threat_types:
            risk_factors.append("Malware activity detected")
        
        # Check for high-confidence threats
        high_confidence_threats = [t for t in threats if t.confidence > 0.8]
        if len(high_confidence_threats) > 0:
            risk_factors.append(f"{len(high_confidence_threats)} high-confidence threat(s)")
        
        return risk_factors[:5]  # Limit to top 5 factors
    
    def _calculate_mitigation_coverage(self, threats: List[Threat]) -> float:
        """Calculate percentage of threats with mitigations."""
        if not threats:
            return 100.0
        
        mitigated_count = sum(1 for t in threats if t.mitigation_status != "open")
        return round((mitigated_count / len(threats)) * 100.0, 1)
    
    def _determine_risk_trend(self, threats: List[Threat]) -> str:
        """Determine risk trend (simplified without historical data)."""
        # In a real implementation, this would compare with historical data
        # For now, use threat recency and severity as indicators
        
        recent_critical = sum(1 for t in threats 
                            if t.severity == ThreatSeverity.CRITICAL and 
                            t.last_seen and 
                            (datetime.now() - t.last_seen).days < 1)
        
        if recent_critical > 0:
            return "deteriorating"
        elif len(threats) == 0:
            return "improving"
        else:
            return "stable"
    
    def _calculate_threat_priority(self, threat: Threat) -> float:
        """Calculate priority score for a single threat."""
        # Base priority from severity (this should be the primary factor)
        base_priority = self.severity_weights.get(threat.severity, 5.0)
        
        # Adjust by confidence (but limit impact to prevent severity inversion)
        confidence_factor = max(threat.confidence, 0.5)  # Minimum 0.5 to prevent severe penalties
        
        # Adjust by business impact (based on threat type)
        impact_multiplier = 1.0
        threat_type_str = threat.threat_type.value
        for impact_type, multiplier in self.business_impact_multipliers.items():
            if impact_type in threat_type_str or impact_type in threat.description.lower():
                impact_multiplier = max(impact_multiplier, multiplier)
        
        # Adjust by scope (number of affected systems)
        scope_factor = min(1.0 + (len(threat.affected_systems) * 0.2), 3.0)
        
        # Calculate final priority with severity dominance
        # Use severity as primary sort key, then apply other factors as secondary
        severity_base = base_priority * 1000  # Make severity the dominant factor
        secondary_factors = confidence_factor * impact_multiplier * scope_factor
        
        priority = severity_base + secondary_factors
        
        return round(priority, 2)
    
    def _assess_revenue_impact(self, threat: Threat) -> str:
        """Assess potential revenue impact of a threat."""
        threat_desc = threat.description.lower()
        threat_type = threat.threat_type.value
        
        # Critical threats should have at least medium revenue impact
        if threat.severity == ThreatSeverity.CRITICAL:
            # High revenue impact scenarios for critical threats
            if any(keyword in threat_desc for keyword in ['payment', 'transaction', 'ecommerce', 'sales']):
                return 'critical'
            elif any(keyword in threat_desc for keyword in ['customer', 'service', 'application']):
                return 'high'
            else:
                return 'medium'  # Minimum for critical threats
        
        # High revenue impact scenarios
        if any(keyword in threat_desc for keyword in ['payment', 'transaction', 'ecommerce', 'sales']):
            return 'critical' if threat.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH] else 'high'
        
        # Medium revenue impact scenarios
        if any(keyword in threat_desc for keyword in ['customer', 'service', 'application']):
            return 'high' if threat.severity == ThreatSeverity.CRITICAL else 'medium'
        
        # Low revenue impact scenarios
        if threat_type in ['configuration_issue', 'compliance_violation']:
            return 'medium' if threat.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH] else 'low'
        
        # Default based on severity
        severity_mapping = {
            ThreatSeverity.CRITICAL: 'high',
            ThreatSeverity.HIGH: 'medium',
            ThreatSeverity.MEDIUM: 'low',
            ThreatSeverity.LOW: 'low'
        }
        return severity_mapping.get(threat.severity, 'low')
    
    def _assess_operational_impact(self, threat: Threat) -> str:
        """Assess potential operational impact of a threat."""
        threat_desc = threat.description.lower()
        affected_systems = len(threat.affected_systems)
        
        # Critical threats should have at least medium operational impact
        if threat.severity == ThreatSeverity.CRITICAL:
            # Critical operational impact
            if any(keyword in threat_desc for keyword in ['outage', 'down', 'unavailable', 'crashed']):
                return 'critical'
            # High operational impact
            elif affected_systems > 5 or any(keyword in threat_desc for keyword in ['degraded', 'slow', 'performance']):
                return 'high'
            else:
                return 'medium'  # Minimum for critical threats
        
        # Critical operational impact
        if any(keyword in threat_desc for keyword in ['outage', 'down', 'unavailable', 'crashed']):
            return 'critical'
        
        # High operational impact
        if affected_systems > 10 or any(keyword in threat_desc for keyword in ['degraded', 'slow', 'performance']):
            return 'high'
        
        # Medium operational impact
        if affected_systems > 3 or threat.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
            return 'medium'
        
        return 'low'
    
    def _assess_compliance_impact(self, threat: Threat) -> str:
        """Assess potential compliance impact of a threat."""
        threat_desc = threat.description.lower()
        threat_type = threat.threat_type.value
        
        # Critical compliance impact
        if threat_type == 'data_breach' or any(keyword in threat_desc for keyword in ['gdpr', 'hipaa', 'pci', 'sox']):
            return 'critical'
        
        # High compliance impact
        if threat_type == 'compliance_violation' or any(keyword in threat_desc for keyword in ['audit', 'regulation', 'policy']):
            return 'high'
        
        # Medium compliance impact
        if any(keyword in threat_desc for keyword in ['access', 'permission', 'authentication']):
            return 'medium'
        
        return 'low'
    
    def _assess_reputation_impact(self, threat: Threat) -> str:
        """Assess potential reputation impact of a threat."""
        threat_desc = threat.description.lower()
        threat_type = threat.threat_type.value
        
        # Critical reputation impact
        if threat_type == 'data_breach' or any(keyword in threat_desc for keyword in ['customer data', 'personal information', 'breach']):
            return 'critical'
        
        # High reputation impact
        if any(keyword in threat_desc for keyword in ['public', 'external', 'customer']):
            return 'high'
        
        # Medium reputation impact
        if threat.severity == ThreatSeverity.CRITICAL:
            return 'medium'
        
        return 'low'
    
    def _generate_business_justification(self, threat: Threat, impacts: Dict[str, str]) -> str:
        """Generate business justification for threat priority."""
        justifications = []
        
        if impacts['revenue'] in ['critical', 'high']:
            justifications.append(f"High revenue impact due to {threat.threat_type.value}")
        
        if impacts['operational'] in ['critical', 'high']:
            justifications.append(f"Significant operational disruption affecting {len(threat.affected_systems)} systems")
        
        if impacts['compliance'] in ['critical', 'high']:
            justifications.append("Potential regulatory compliance violations")
        
        if impacts['reputation'] in ['critical', 'high']:
            justifications.append("Risk of reputation damage and customer trust loss")
        
        if not justifications:
            justifications.append("Standard security risk requiring attention")
        
        return "; ".join(justifications)
    
    def _generate_immediate_actions(self, threat: Threat, business_impact: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate immediate actions for critical threats."""
        actions = []
        
        if threat.threat_type.value == 'malware':
            actions.append({
                'action': 'Isolate affected systems immediately',
                'timeline': 'Within 15 minutes',
                'owner': 'Security Team',
                'business_justification': business_impact['business_justification']
            })
        elif threat.threat_type.value == 'data_breach':
            actions.append({
                'action': 'Activate incident response team and legal counsel',
                'timeline': 'Within 30 minutes',
                'owner': 'CISO/Legal',
                'business_justification': 'Regulatory notification requirements'
            })
        elif threat.threat_type.value == 'intrusion':
            actions.append({
                'action': 'Change all administrative passwords',
                'timeline': 'Within 1 hour',
                'owner': 'IT Security',
                'business_justification': 'Prevent further unauthorized access'
            })
        elif threat.threat_type.value == 'insider_threat':
            actions.append({
                'action': 'Suspend user access and initiate investigation',
                'timeline': 'Within 30 minutes',
                'owner': 'HR/Security Team',
                'business_justification': business_impact['business_justification']
            })
        elif threat.threat_type.value == 'ddos':
            actions.append({
                'action': 'Activate DDoS mitigation and contact ISP',
                'timeline': 'Within 15 minutes',
                'owner': 'Network Operations',
                'business_justification': 'Restore service availability'
            })
        else:
            # Generic immediate action for any critical threat
            actions.append({
                'action': f'Initiate emergency response for {threat.threat_type.value}',
                'timeline': 'Within 1 hour',
                'owner': 'Security Team',
                'business_justification': business_impact['business_justification']
            })
        
        return actions
    
    def _generate_short_term_actions(self, threat: Threat, business_impact: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate short-term actions for high severity threats."""
        actions = []
        
        actions.append({
            'action': f'Conduct detailed forensic analysis of {threat.title}',
            'timeline': 'Within 24-48 hours',
            'owner': 'Security Team',
            'business_justification': business_impact['business_justification']
        })
        
        if len(threat.affected_systems) > 1:
            actions.append({
                'action': 'Implement additional monitoring on affected systems',
                'timeline': 'Within 72 hours',
                'owner': 'SOC Team',
                'business_justification': 'Prevent lateral movement and detect similar threats'
            })
        
        return actions
    
    def _generate_long_term_actions(self, threat: Threat, business_impact: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate long-term actions for medium/low severity threats."""
        actions = []
        
        actions.append({
            'action': f'Review and update security policies related to {threat.threat_type.value}',
            'timeline': 'Within 2-4 weeks',
            'owner': 'Security Team',
            'business_justification': 'Prevent similar threats in the future'
        })
        
        if threat.threat_type.value == 'configuration_issue':
            actions.append({
                'action': 'Implement configuration management and monitoring',
                'timeline': 'Within 1 month',
                'owner': 'IT Operations',
                'business_justification': 'Reduce configuration drift and security gaps'
            })
        
        return actions
    
    def _generate_resource_allocation_guidance(self, threats: List[Threat]) -> Dict[str, Any]:
        """Generate guidance for resource allocation."""
        critical_count = sum(1 for t in threats if t.severity == ThreatSeverity.CRITICAL)
        high_count = sum(1 for t in threats if t.severity == ThreatSeverity.HIGH)
        
        if critical_count > 0:
            return {
                'priority': 'All hands on deck',
                'staffing': 'Mobilize entire security team',
                'budget': 'Approve emergency security spending',
                'timeline': 'Immediate response required'
            }
        elif high_count > 3:
            return {
                'priority': 'High priority response',
                'staffing': 'Assign dedicated security analysts',
                'budget': 'Allocate additional security resources',
                'timeline': 'Response within 24 hours'
            }
        else:
            return {
                'priority': 'Standard response',
                'staffing': 'Regular security team capacity',
                'budget': 'Standard security budget',
                'timeline': 'Response within normal SLA'
            }
    
    def _generate_escalation_matrix(self, threats: List[Threat]) -> Dict[str, List[str]]:
        """Generate escalation matrix based on threat severity."""
        critical_threats = [t for t in threats if t.severity == ThreatSeverity.CRITICAL]
        high_threats = [t for t in threats if t.severity == ThreatSeverity.HIGH]
        
        matrix = {}
        
        if critical_threats:
            matrix['immediate_escalation'] = [
                'CISO/Security Director',
                'CTO/IT Director', 
                'CEO (for data breaches)',
                'Legal Counsel (for compliance issues)'
            ]
        
        if high_threats:
            matrix['24_hour_escalation'] = [
                'Security Manager',
                'IT Manager',
                'Business Unit Leaders (if business impact)'
            ]
        
        matrix['regular_reporting'] = [
            'Security Team Lead',
            'IT Operations Manager'
        ]
        
        return matrix
    
    def _determine_overall_priority(self, threats: List[Threat]) -> str:
        """Determine overall priority level for the threat landscape."""
        if any(t.severity == ThreatSeverity.CRITICAL for t in threats):
            return 'critical'
        elif len([t for t in threats if t.severity == ThreatSeverity.HIGH]) > 2:
            return 'high'
        elif len(threats) > 5:
            return 'medium'
        else:
            return 'low'