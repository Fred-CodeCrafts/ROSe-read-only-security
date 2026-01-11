"""
Access Pattern Analyzer

Analyzes access patterns for least-privilege recommendations and security intelligence.
Implements comprehensive access pattern analysis and blast radius assessment.
"""

import logging
import datetime
from typing import List, Dict, Any, Optional, Tuple, Set
from collections import defaultdict, Counter
from dataclasses import dataclass
from .models import AccessPattern, BlastRadiusAssessment, DataClassification


@dataclass
class AccessRecommendation:
    """Recommendation for access pattern improvement"""
    user_id: str
    resource: str
    current_permissions: List[str]
    recommended_permissions: List[str]
    risk_reduction: float
    justification: str


@dataclass
class SecurityPostureAssessment:
    """Overall security posture assessment"""
    overall_score: float
    risk_level: str
    critical_findings: List[str]
    recommendations: List[str]
    improvement_areas: List[str]
    compliance_status: Dict[str, bool]


class AccessPatternAnalyzer:
    """
    Analyzes access patterns to provide least-privilege recommendations
    and comprehensive security intelligence reporting.
    """
    
    # Risk scoring weights
    RISK_WEIGHTS = {
        'failed_attempts': 0.3,
        'unusual_hours': 0.2,
        'geographic_anomaly': 0.25,
        'privilege_escalation': 0.4,
        'data_sensitivity': 0.35,
        'frequency_anomaly': 0.15,
    }
    
    # Time-based risk factors
    UNUSUAL_HOURS = {
        'start': 22,  # 10 PM
        'end': 6,     # 6 AM
    }
    
    def __init__(self):
        """Initialize the access pattern analyzer"""
        self.logger = logging.getLogger(__name__)
        
    def analyze_access_patterns(self, access_logs: List[AccessPattern]) -> Dict[str, Any]:
        """
        Analyze access patterns for security insights and recommendations.
        
        Args:
            access_logs: List of access pattern records
            
        Returns:
            Comprehensive access pattern analysis report
        """
        if not access_logs:
            return self._empty_analysis_report()
        
        # Group access patterns by user
        user_patterns = self._group_by_user(access_logs)
        
        # Analyze each user's patterns
        user_analyses = {}
        for user_id, patterns in user_patterns.items():
            user_analyses[user_id] = self._analyze_user_patterns(user_id, patterns)
        
        # Generate system-wide insights
        system_insights = self._generate_system_insights(access_logs, user_analyses)
        
        # Create recommendations
        recommendations = self._generate_access_recommendations(user_analyses)
        
        report = {
            'analysis_timestamp': datetime.datetime.now().isoformat(),
            'total_access_events': len(access_logs),
            'unique_users': len(user_patterns),
            'user_analyses': user_analyses,
            'system_insights': system_insights,
            'recommendations': recommendations,
            'risk_summary': self._calculate_risk_summary(user_analyses),
        }
        
        self.logger.info(f"Analyzed {len(access_logs)} access events for {len(user_patterns)} users")
        
        return report
    
    def _group_by_user(self, access_logs: List[AccessPattern]) -> Dict[str, List[AccessPattern]]:
        """Group access patterns by user ID"""
        user_patterns = defaultdict(list)
        for pattern in access_logs:
            user_patterns[pattern.user_id].append(pattern)
        return dict(user_patterns)
    
    def _analyze_user_patterns(self, user_id: str, patterns: List[AccessPattern]) -> Dict[str, Any]:
        """Analyze access patterns for a specific user"""
        # Basic statistics
        total_accesses = len(patterns)
        successful_accesses = sum(1 for p in patterns if p.success)
        failed_accesses = total_accesses - successful_accesses
        
        # Resource access analysis
        resource_counts = Counter(p.resource for p in patterns)
        action_counts = Counter(p.action for p in patterns)
        
        # Time-based analysis
        time_analysis = self._analyze_time_patterns(patterns)
        
        # Risk assessment
        risk_score = self._calculate_user_risk_score(patterns)
        
        # Anomaly detection
        anomalies = self._detect_access_anomalies(patterns)
        
        return {
            'user_id': user_id,
            'total_accesses': total_accesses,
            'successful_accesses': successful_accesses,
            'failed_accesses': failed_accesses,
            'success_rate': successful_accesses / total_accesses if total_accesses > 0 else 0,
            'resource_access_counts': dict(resource_counts),
            'action_counts': dict(action_counts),
            'time_analysis': time_analysis,
            'risk_score': risk_score,
            'anomalies': anomalies,
            'most_accessed_resources': resource_counts.most_common(5),
            'privilege_level': self._assess_privilege_level(patterns),
        }
    
    def _analyze_time_patterns(self, patterns: List[AccessPattern]) -> Dict[str, Any]:
        """Analyze temporal access patterns"""
        if not patterns:
            return {}
        
        # Extract hours from timestamps
        hours = [p.timestamp.hour for p in patterns]
        hour_counts = Counter(hours)
        
        # Detect unusual hour accesses
        unusual_hour_accesses = sum(
            1 for hour in hours 
            if hour >= self.UNUSUAL_HOURS['start'] or hour <= self.UNUSUAL_HOURS['end']
        )
        
        # Calculate time-based metrics
        return {
            'hourly_distribution': dict(hour_counts),
            'unusual_hour_accesses': unusual_hour_accesses,
            'unusual_hour_percentage': unusual_hour_accesses / len(patterns) if patterns else 0,
            'peak_access_hour': hour_counts.most_common(1)[0][0] if hour_counts else None,
            'access_time_span_hours': self._calculate_time_span(patterns),
        }
    
    def _calculate_time_span(self, patterns: List[AccessPattern]) -> float:
        """Calculate the time span of access patterns in hours"""
        if len(patterns) < 2:
            return 0.0
        
        timestamps = [p.timestamp for p in patterns]
        time_span = max(timestamps) - min(timestamps)
        return time_span.total_seconds() / 3600  # Convert to hours
    
    def _calculate_user_risk_score(self, patterns: List[AccessPattern]) -> float:
        """Calculate risk score for a user based on access patterns"""
        if not patterns:
            return 0.0
        
        risk_factors = {
            'failed_attempts': 0.0,
            'unusual_hours': 0.0,
            'privilege_escalation': 0.0,
            'frequency_anomaly': 0.0,
        }
        
        # Failed attempts risk
        failed_rate = sum(1 for p in patterns if not p.success) / len(patterns)
        risk_factors['failed_attempts'] = min(failed_rate * 2, 1.0)  # Cap at 1.0
        
        # Unusual hours risk
        unusual_hours = sum(
            1 for p in patterns 
            if p.timestamp.hour >= self.UNUSUAL_HOURS['start'] or p.timestamp.hour <= self.UNUSUAL_HOURS['end']
        )
        risk_factors['unusual_hours'] = min(unusual_hours / len(patterns) * 3, 1.0)
        
        # Privilege escalation risk (based on action diversity)
        unique_actions = len(set(p.action for p in patterns))
        if unique_actions > 5:  # Many different actions might indicate privilege escalation
            risk_factors['privilege_escalation'] = min(unique_actions / 10, 1.0)
        
        # Frequency anomaly (very high or very low frequency)
        time_span_hours = self._calculate_time_span(patterns)
        if time_span_hours > 0:
            access_frequency = len(patterns) / time_span_hours
            if access_frequency > 10:  # More than 10 accesses per hour
                risk_factors['frequency_anomaly'] = min(access_frequency / 20, 1.0)
        
        # Calculate weighted risk score
        total_risk = sum(
            risk_factors[factor] * self.RISK_WEIGHTS[factor]
            for factor in risk_factors
        )
        
        return min(total_risk, 1.0)
    
    def _detect_access_anomalies(self, patterns: List[AccessPattern]) -> List[str]:
        """Detect anomalies in access patterns"""
        anomalies = []
        
        if not patterns:
            return anomalies
        
        # Check for rapid successive failures
        failed_patterns = [p for p in patterns if not p.success]
        if len(failed_patterns) >= 3:
            # Check if failures are within a short time window
            failed_patterns.sort(key=lambda x: x.timestamp)
            for i in range(len(failed_patterns) - 2):
                time_diff = failed_patterns[i + 2].timestamp - failed_patterns[i].timestamp
                if time_diff.total_seconds() < 300:  # 5 minutes
                    anomalies.append("Rapid successive authentication failures detected")
                    break
        
        # Check for unusual resource access patterns
        resource_counts = Counter(p.resource for p in patterns)
        if len(resource_counts) > 20:  # Accessing many different resources
            anomalies.append("Unusually broad resource access pattern")
        
        # Check for geographic anomalies (if IP addresses vary significantly)
        ip_addresses = set(p.source_ip for p in patterns if p.source_ip)
        if len(ip_addresses) > 5:  # Many different IP addresses
            anomalies.append("Multiple source IP addresses detected")
        
        return anomalies
    
    def _assess_privilege_level(self, patterns: List[AccessPattern]) -> str:
        """Assess the privilege level based on access patterns"""
        if not patterns:
            return "unknown"
        
        # Count privileged actions
        privileged_actions = {'create', 'delete', 'modify', 'admin', 'configure', 'manage'}
        privileged_count = sum(
            1 for p in patterns 
            if any(priv in p.action.lower() for priv in privileged_actions)
        )
        
        privileged_ratio = privileged_count / len(patterns)
        
        if privileged_ratio > 0.7:
            return "high"
        elif privileged_ratio > 0.3:
            return "medium"
        else:
            return "low"
    
    def _generate_system_insights(self, access_logs: List[AccessPattern], 
                                user_analyses: Dict[str, Any]) -> Dict[str, Any]:
        """Generate system-wide security insights"""
        # Overall statistics
        total_users = len(user_analyses)
        high_risk_users = sum(1 for analysis in user_analyses.values() if analysis['risk_score'] > 0.7)
        
        # Resource access patterns
        all_resources = [log.resource for log in access_logs]
        resource_popularity = Counter(all_resources)
        
        # Time-based insights
        all_hours = [log.timestamp.hour for log in access_logs]
        peak_hours = Counter(all_hours).most_common(3)
        
        return {
            'total_users': total_users,
            'high_risk_users': high_risk_users,
            'high_risk_percentage': high_risk_users / total_users if total_users > 0 else 0,
            'most_accessed_resources': resource_popularity.most_common(10),
            'peak_access_hours': peak_hours,
            'overall_success_rate': sum(1 for log in access_logs if log.success) / len(access_logs),
            'unique_resources_accessed': len(set(all_resources)),
            'average_user_risk_score': sum(analysis['risk_score'] for analysis in user_analyses.values()) / total_users if total_users > 0 else 0,
        }
    
    def _generate_access_recommendations(self, user_analyses: Dict[str, Any]) -> List[AccessRecommendation]:
        """Generate least-privilege access recommendations"""
        recommendations = []
        
        for user_id, analysis in user_analyses.items():
            # High-risk users need immediate attention
            if analysis['risk_score'] > 0.7:
                recommendations.append(AccessRecommendation(
                    user_id=user_id,
                    resource="all",
                    current_permissions=["broad_access"],
                    recommended_permissions=["restricted_access"],
                    risk_reduction=0.5,
                    justification=f"High risk score ({analysis['risk_score']:.2f}) requires access restriction"
                ))
            
            # Users with many failed attempts
            if analysis['failed_accesses'] > 10:
                recommendations.append(AccessRecommendation(
                    user_id=user_id,
                    resource="authentication",
                    current_permissions=["unlimited_attempts"],
                    recommended_permissions=["rate_limited_attempts"],
                    risk_reduction=0.3,
                    justification=f"High failure rate ({analysis['failed_accesses']} failures) suggests need for rate limiting"
                ))
            
            # Users accessing too many resources
            if len(analysis['resource_access_counts']) > 15:
                recommendations.append(AccessRecommendation(
                    user_id=user_id,
                    resource="resource_scope",
                    current_permissions=["broad_resource_access"],
                    recommended_permissions=["scoped_resource_access"],
                    risk_reduction=0.4,
                    justification=f"Access to {len(analysis['resource_access_counts'])} resources exceeds typical usage patterns"
                ))
        
        return recommendations
    
    def _calculate_risk_summary(self, user_analyses: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk summary"""
        if not user_analyses:
            return {}
        
        risk_scores = [analysis['risk_score'] for analysis in user_analyses.values()]
        
        return {
            'average_risk_score': sum(risk_scores) / len(risk_scores),
            'max_risk_score': max(risk_scores),
            'min_risk_score': min(risk_scores),
            'high_risk_users': sum(1 for score in risk_scores if score > 0.7),
            'medium_risk_users': sum(1 for score in risk_scores if 0.3 <= score <= 0.7),
            'low_risk_users': sum(1 for score in risk_scores if score < 0.3),
        }
    
    def _empty_analysis_report(self) -> Dict[str, Any]:
        """Return empty analysis report when no data is available"""
        return {
            'analysis_timestamp': datetime.datetime.now().isoformat(),
            'total_access_events': 0,
            'unique_users': 0,
            'user_analyses': {},
            'system_insights': {},
            'recommendations': [],
            'risk_summary': {},
            'message': 'No access patterns available for analysis'
        }


class BlastRadiusAnalyzer:
    """
    Analyzes potential blast radius for security incidents and provides
    containment analysis and impact prediction.
    """
    
    # Service dependency mapping (simplified example)
    SERVICE_DEPENDENCIES = {
        'web_server': ['database', 'cache', 'auth_service'],
        'api_gateway': ['web_server', 'auth_service', 'rate_limiter'],
        'database': ['backup_service', 'monitoring'],
        'auth_service': ['user_store', 'session_store'],
        'payment_service': ['database', 'external_payment_api'],
    }
    
    # Region interconnections
    REGION_CONNECTIONS = {
        'us-east-1': ['us-west-2', 'eu-west-1'],
        'us-west-2': ['us-east-1', 'ap-southeast-1'],
        'eu-west-1': ['us-east-1', 'eu-central-1'],
    }
    
    def __init__(self):
        """Initialize the blast radius analyzer"""
        self.logger = logging.getLogger(__name__)
    
    def assess_blast_radius(self, incident_service: str, incident_region: str, 
                          incident_account: str, severity: str = "medium") -> BlastRadiusAssessment:
        """
        Assess the potential blast radius of a security incident.
        
        Args:
            incident_service: Service where incident occurred
            incident_region: Region where incident occurred  
            incident_account: Account where incident occurred
            severity: Incident severity (low, medium, high, critical)
            
        Returns:
            BlastRadiusAssessment with impact analysis and recommendations
        """
        # Calculate affected services
        affected_services = self._calculate_affected_services(incident_service, severity)
        
        # Calculate affected regions
        affected_regions = self._calculate_affected_regions(incident_region, severity)
        
        # Calculate affected accounts (simplified - in real scenario would be more complex)
        affected_accounts = self._calculate_affected_accounts(incident_account, severity)
        
        # Calculate impact score
        impact_score = self._calculate_impact_score(
            len(affected_services), len(affected_regions), len(affected_accounts), severity
        )
        
        # Generate containment recommendations
        containment_recommendations = self._generate_containment_recommendations(
            incident_service, affected_services, severity
        )
        
        # Estimate recovery time
        recovery_time = self._estimate_recovery_time(affected_services, severity)
        
        # Determine risk level
        risk_level = self._determine_risk_level(impact_score)
        
        assessment = BlastRadiusAssessment(
            affected_services=affected_services,
            affected_regions=affected_regions,
            affected_accounts=affected_accounts,
            impact_score=impact_score,
            containment_recommendations=containment_recommendations,
            estimated_recovery_time=recovery_time,
            risk_level=risk_level
        )
        
        self.logger.info(f"Blast radius assessment: {len(affected_services)} services, "
                        f"{len(affected_regions)} regions, impact score {impact_score:.2f}")
        
        return assessment
    
    def _calculate_affected_services(self, incident_service: str, severity: str) -> List[str]:
        """Calculate services that could be affected by the incident"""
        affected = [incident_service]
        
        # Add direct dependencies
        if incident_service in self.SERVICE_DEPENDENCIES:
            affected.extend(self.SERVICE_DEPENDENCIES[incident_service])
        
        # For high/critical severity, include services that depend on the incident service
        if severity in ['high', 'critical']:
            for service, deps in self.SERVICE_DEPENDENCIES.items():
                if incident_service in deps and service not in affected:
                    affected.append(service)
        
        # For critical severity, include second-level dependencies
        if severity == 'critical':
            second_level = []
            for service in affected[1:]:  # Skip the original incident service
                if service in self.SERVICE_DEPENDENCIES:
                    second_level.extend(self.SERVICE_DEPENDENCIES[service])
            affected.extend([s for s in second_level if s not in affected])
        
        return affected
    
    def _calculate_affected_regions(self, incident_region: str, severity: str) -> List[str]:
        """Calculate regions that could be affected"""
        affected = [incident_region]
        
        # For medium+ severity, include connected regions
        if severity in ['medium', 'high', 'critical']:
            if incident_region in self.REGION_CONNECTIONS:
                affected.extend(self.REGION_CONNECTIONS[incident_region])
        
        # For critical severity, include all regions (global impact)
        if severity == 'critical':
            all_regions = set([incident_region])
            for region, connections in self.REGION_CONNECTIONS.items():
                all_regions.add(region)
                all_regions.update(connections)
            affected = list(all_regions)
        
        return list(set(affected))  # Remove duplicates
    
    def _calculate_affected_accounts(self, incident_account: str, severity: str) -> List[str]:
        """Calculate accounts that could be affected"""
        affected = [incident_account]
        
        # For high/critical severity, assume cross-account impact
        if severity in ['high', 'critical']:
            # In a real scenario, this would analyze actual cross-account relationships
            affected.extend([f"{incident_account}_prod", f"{incident_account}_staging"])
        
        return affected
    
    def _calculate_impact_score(self, num_services: int, num_regions: int, 
                              num_accounts: int, severity: str) -> float:
        """Calculate overall impact score"""
        # Base score from severity
        severity_scores = {
            'low': 0.2,
            'medium': 0.4,
            'high': 0.7,
            'critical': 1.0
        }
        base_score = severity_scores.get(severity, 0.4)
        
        # Scale based on scope
        service_factor = min(num_services / 10, 1.0)  # Normalize to max 10 services
        region_factor = min(num_regions / 5, 1.0)     # Normalize to max 5 regions
        account_factor = min(num_accounts / 3, 1.0)   # Normalize to max 3 accounts
        
        # Weighted combination
        impact_score = (
            base_score * 0.4 +
            service_factor * 0.3 +
            region_factor * 0.2 +
            account_factor * 0.1
        )
        
        return min(impact_score, 1.0)
    
    def _generate_containment_recommendations(self, incident_service: str, 
                                            affected_services: List[str], severity: str) -> List[str]:
        """Generate containment recommendations"""
        recommendations = []
        
        # Immediate containment
        recommendations.append(f"Isolate {incident_service} to prevent further spread")
        
        # Service-specific recommendations
        if 'database' in affected_services:
            recommendations.append("Enable database read-only mode to prevent data corruption")
        
        if 'auth_service' in affected_services:
            recommendations.append("Implement emergency authentication bypass for critical operations")
        
        if 'payment_service' in affected_services:
            recommendations.append("Halt all payment processing and notify payment providers")
        
        # Severity-based recommendations
        if severity in ['high', 'critical']:
            recommendations.append("Activate incident response team and establish war room")
            recommendations.append("Prepare customer communication and status page updates")
        
        if severity == 'critical':
            recommendations.append("Consider activating disaster recovery procedures")
            recommendations.append("Notify executive leadership and legal team")
        
        # Monitoring recommendations
        recommendations.append("Increase monitoring frequency for all affected services")
        recommendations.append("Set up dedicated alerting for containment verification")
        
        return recommendations
    
    def _estimate_recovery_time(self, affected_services: List[str], severity: str) -> str:
        """Estimate recovery time based on affected services and severity"""
        # Base recovery times by service type (in hours)
        service_recovery_times = {
            'web_server': 1,
            'api_gateway': 2,
            'database': 4,
            'auth_service': 3,
            'payment_service': 6,
            'backup_service': 2,
            'monitoring': 1,
        }
        
        # Calculate total recovery time
        total_time = 0
        for service in affected_services:
            total_time += service_recovery_times.get(service, 2)  # Default 2 hours
        
        # Adjust for severity
        severity_multipliers = {
            'low': 0.5,
            'medium': 1.0,
            'high': 1.5,
            'critical': 2.0
        }
        
        total_time *= severity_multipliers.get(severity, 1.0)
        
        # Convert to human-readable format
        if total_time < 1:
            return "< 1 hour"
        elif total_time < 24:
            return f"{int(total_time)} hours"
        else:
            days = int(total_time / 24)
            hours = int(total_time % 24)
            return f"{days} days, {hours} hours"
    
    def _determine_risk_level(self, impact_score: float) -> str:
        """Determine risk level based on impact score"""
        if impact_score >= 0.8:
            return "critical"
        elif impact_score >= 0.6:
            return "high"
        elif impact_score >= 0.3:
            return "medium"
        else:
            return "low"
    
    def generate_security_posture_assessment(self, access_analysis: Dict[str, Any], 
                                           blast_radius_assessments: List[BlastRadiusAssessment]) -> SecurityPostureAssessment:
        """
        Generate comprehensive security posture assessment.
        
        Args:
            access_analysis: Results from access pattern analysis
            blast_radius_assessments: List of blast radius assessments
            
        Returns:
            SecurityPostureAssessment with overall security posture
        """
        # Calculate overall score
        access_score = 1.0 - access_analysis.get('risk_summary', {}).get('average_risk_score', 0.5)
        
        blast_radius_scores = [1.0 - assessment.impact_score for assessment in blast_radius_assessments]
        avg_blast_radius_score = sum(blast_radius_scores) / len(blast_radius_scores) if blast_radius_scores else 0.8
        
        overall_score = (access_score * 0.6 + avg_blast_radius_score * 0.4)
        
        # Determine risk level
        if overall_score >= 0.8:
            risk_level = "low"
        elif overall_score >= 0.6:
            risk_level = "medium"
        elif overall_score >= 0.4:
            risk_level = "high"
        else:
            risk_level = "critical"
        
        # Generate findings and recommendations
        critical_findings = []
        recommendations = []
        improvement_areas = []
        
        # Access-based findings
        high_risk_users = access_analysis.get('system_insights', {}).get('high_risk_users', 0)
        if high_risk_users > 0:
            critical_findings.append(f"{high_risk_users} high-risk users identified")
            recommendations.append("Implement additional monitoring for high-risk users")
            improvement_areas.append("User access management")
        
        # Blast radius findings
        critical_assessments = [a for a in blast_radius_assessments if a.risk_level == 'critical']
        if critical_assessments:
            critical_findings.append(f"{len(critical_assessments)} critical blast radius scenarios identified")
            recommendations.append("Implement additional service isolation and containment measures")
            improvement_areas.append("Service architecture resilience")
        
        # Compliance status (simplified)
        compliance_status = {
            'access_logging': access_analysis.get('total_access_events', 0) > 0,
            'risk_assessment': len(blast_radius_assessments) > 0,
            'incident_response': len(critical_assessments) == 0,
            'least_privilege': access_analysis.get('system_insights', {}).get('high_risk_percentage', 1.0) < 0.1,
        }
        
        return SecurityPostureAssessment(
            overall_score=overall_score,
            risk_level=risk_level,
            critical_findings=critical_findings,
            recommendations=recommendations,
            improvement_areas=improvement_areas,
            compliance_status=compliance_status
        )