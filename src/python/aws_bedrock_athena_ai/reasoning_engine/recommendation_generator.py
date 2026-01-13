"""
Recommendation Generator - Creates actionable security recommendations.

This module generates specific, actionable security recommendations based on
threat analysis and risk assessment results.
"""

import json
import logging
import uuid
from typing import List, Dict, Any

import boto3
from botocore.exceptions import ClientError

from aws_bedrock_athena_ai.reasoning_engine.models import Threat, Recommendation, ThreatSeverity, ThreatType


logger = logging.getLogger(__name__)


class RecommendationGenerator:
    """
    Generates actionable security recommendations based on threat analysis.
    """
    
    def __init__(self, region_name: str = "us-east-1"):
        """Initialize the recommendation generator."""
        self.bedrock_client = boto3.client('bedrock-runtime', region_name=region_name)
        self.model_id = "anthropic.claude-3-haiku-20240307-v1:0"
        
        # Pre-defined recommendation templates for common scenarios
        self.recommendation_templates = {
            ThreatType.MALWARE: {
                'priority': 'critical',
                'category': 'incident_response',
                'base_steps': [
                    'Isolate affected systems immediately',
                    'Run full antimalware scan',
                    'Check for lateral movement',
                    'Update security signatures'
                ]
            },
            ThreatType.INTRUSION: {
                'priority': 'critical',
                'category': 'incident_response',
                'base_steps': [
                    'Change all compromised credentials',
                    'Review access logs for unauthorized activity',
                    'Patch identified vulnerabilities',
                    'Implement additional monitoring'
                ]
            },
            ThreatType.VULNERABILITY: {
                'priority': 'high',
                'category': 'vulnerability_management',
                'base_steps': [
                    'Apply security patches immediately',
                    'Implement temporary mitigations',
                    'Scan for similar vulnerabilities',
                    'Update vulnerability management process'
                ]
            },
            ThreatType.CONFIGURATION_ISSUE: {
                'priority': 'medium',
                'category': 'configuration_management',
                'base_steps': [
                    'Review and correct configuration',
                    'Implement configuration monitoring',
                    'Document secure configuration standards',
                    'Train team on secure configurations'
                ]
            }
        }
    
    def generate_specific_remediation_steps(self, threats: List[Threat]) -> List[Recommendation]:
        """
        Generate specific, detailed remediation steps for identified threats.
        
        Args:
            threats: List of threats requiring remediation
            
        Returns:
            List of detailed recommendations with specific steps
        """
        try:
            logger.info(f"Generating specific remediation steps for {len(threats)} threats")
            
            recommendations = []
            
            for threat in threats:
                # Generate threat-specific recommendations
                threat_recommendations = self._generate_threat_specific_recommendations(threat)
                recommendations.extend(threat_recommendations)
            
            # Generate system-wide recommendations
            system_recommendations = self._generate_system_wide_recommendations(threats)
            recommendations.extend(system_recommendations)
            
            # Add detailed implementation steps
            detailed_recommendations = []
            for rec in recommendations:
                detailed_rec = self._add_detailed_implementation_steps(rec, threats)
                detailed_recommendations.append(detailed_rec)
            
            return detailed_recommendations
            
        except Exception as e:
            logger.error(f"Error generating specific remediation steps: {str(e)}")
            return []
    
    def generate_cost_benefit_analysis_detailed(self, recommendations: List[Recommendation], threats: List[Threat]) -> List[Recommendation]:
        """
        Generate detailed cost-benefit analysis for security improvements.
        
        Args:
            recommendations: List of recommendations to analyze
            threats: Related threats for context
            
        Returns:
            Recommendations with detailed cost-benefit analysis
        """
        try:
            for recommendation in recommendations:
                # Calculate detailed costs
                cost_analysis = self._calculate_detailed_costs(recommendation)
                
                # Calculate detailed benefits
                benefit_analysis = self._calculate_detailed_benefits(recommendation, threats)
                
                # Calculate ROI and payback period
                roi_analysis = self._calculate_roi_analysis(cost_analysis, benefit_analysis)
                
                # Add analysis to recommendation
                recommendation.cost_analysis = cost_analysis
                recommendation.benefit_analysis = benefit_analysis
                recommendation.roi_analysis = roi_analysis
                recommendation.cost_benefit_ratio = roi_analysis['roi_ratio']
                
                # Update business impact with financial context
                recommendation.business_impact = self._enhance_business_impact_with_financials(
                    recommendation.business_impact, 
                    cost_analysis, 
                    benefit_analysis
                )
            
            # Sort by ROI
            recommendations.sort(key=lambda r: getattr(r, 'roi_analysis', {}).get('roi_ratio', 0), reverse=True)
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating detailed cost-benefit analysis: {str(e)}")
            return recommendations
    
    def generate_recommendations(self, threats: List[Threat]) -> List[Recommendation]:
        """
        Generate actionable recommendations for identified threats.
        
        Args:
            threats: List of identified threats
            
        Returns:
            List of prioritized recommendations
        """
        try:
            logger.info(f"Generating recommendations for {len(threats)} threats")
            
            recommendations = []
            
            # Generate AI-powered recommendations
            ai_recommendations = self._generate_ai_recommendations(threats)
            recommendations.extend(ai_recommendations)
            
            # Generate template-based recommendations for quick response
            template_recommendations = self._generate_template_recommendations(threats)
            recommendations.extend(template_recommendations)
            
            # Remove duplicates and prioritize
            unique_recommendations = self._deduplicate_recommendations(recommendations)
            prioritized_recommendations = self._prioritize_recommendations(unique_recommendations)
            
            logger.info(f"Generated {len(prioritized_recommendations)} unique recommendations")
            return prioritized_recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            return []
    
    def generate_cost_benefit_analysis(self, recommendations: List[Recommendation]) -> List[Recommendation]:
        """
        Add cost-benefit analysis to recommendations.
        
        Args:
            recommendations: List of recommendations to analyze
            
        Returns:
            Recommendations with cost-benefit ratios
        """
        try:
            for recommendation in recommendations:
                # Simple cost-benefit calculation based on priority and effort
                benefit_score = self._calculate_benefit_score(recommendation)
                cost_score = self._calculate_cost_score(recommendation)
                
                if cost_score > 0:
                    recommendation.cost_benefit_ratio = round(benefit_score / cost_score, 2)
                else:
                    recommendation.cost_benefit_ratio = float('inf')  # High benefit, no cost
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error calculating cost-benefit analysis: {str(e)}")
            return recommendations
    
    def _generate_ai_recommendations(self, threats: List[Threat]) -> List[Recommendation]:
        """Generate recommendations using AI analysis."""
        try:
            if not threats:
                return []
            
            # Prepare threat summary for AI
            threat_summary = self._prepare_threat_summary(threats)
            
            # Build recommendation prompt
            prompt = self._build_recommendation_prompt(threat_summary)
            
            # Get AI recommendations
            ai_response = self._call_bedrock_model(prompt)
            
            # Parse AI response
            recommendations = self._parse_ai_recommendations(ai_response, threats)
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating AI recommendations: {str(e)}")
            return []
    
    def _generate_template_recommendations(self, threats: List[Threat]) -> List[Recommendation]:
        """Generate recommendations using predefined templates."""
        recommendations = []
        
        for threat in threats:
            template = self.recommendation_templates.get(threat.threat_type)
            if template:
                recommendation = Recommendation(
                    recommendation_id=str(uuid.uuid4()),
                    priority=template['priority'],
                    category=template['category'],
                    title=f"Address {threat.threat_type.value} - {threat.title}",
                    description=f"Immediate response required for {threat.threat_type.value} threat",
                    implementation_steps=template['base_steps'].copy(),
                    estimated_effort=self._estimate_effort(threat.severity),
                    business_impact=self._assess_business_impact(threat),
                    related_threats=[threat.threat_id]
                )
                recommendations.append(recommendation)
        
        return recommendations
    
    def _build_recommendation_prompt(self, threat_summary: str) -> str:
        """Build prompt for AI recommendation generation."""
        prompt = f"""
You are a senior cybersecurity consultant providing actionable recommendations to a client. 
Based on the following threat analysis, provide specific, prioritized security recommendations.

Threat Analysis Summary:
{threat_summary}

For each recommendation, provide:
1. Clear, actionable title
2. Detailed description of what needs to be done
3. Step-by-step implementation guide
4. Estimated effort (hours/days/weeks)
5. Business impact explanation
6. Priority level (critical/high/medium/low)

Focus on:
- Immediate threat mitigation
- Long-term security improvements
- Cost-effective solutions
- Business-friendly explanations

Format your response as JSON:
{{
  "recommendations": [
    {{
      "title": "Recommendation title",
      "description": "Detailed description",
      "priority": "critical|high|medium|low",
      "category": "incident_response|vulnerability_management|access_control|monitoring|training|policy",
      "implementation_steps": [
        "Step 1: Specific action",
        "Step 2: Specific action"
      ],
      "estimated_effort": "2 hours|3 days|1 week",
      "business_impact": "Explanation of business value",
      "related_threat_types": ["malware", "intrusion"]
    }}
  ]
}}

Provide 3-7 recommendations prioritized by urgency and impact.
"""
        return prompt
    
    def _prepare_threat_summary(self, threats: List[Threat]) -> str:
        """Prepare a summary of threats for AI analysis."""
        summary_parts = []
        
        # Group threats by type and severity
        threat_groups = {}
        for threat in threats:
            key = f"{threat.threat_type.value}_{threat.severity.value}"
            if key not in threat_groups:
                threat_groups[key] = []
            threat_groups[key].append(threat)
        
        # Create summary for each group
        for group_key, group_threats in threat_groups.items():
            threat_type, severity = group_key.split('_')
            count = len(group_threats)
            
            # Get representative threat details
            representative = group_threats[0]
            affected_systems = set()
            for t in group_threats:
                affected_systems.update(t.affected_systems)
            
            summary_parts.append(f"""
{count} {severity.upper()} {threat_type} threat(s):
- Representative: {representative.title}
- Description: {representative.description}
- Affected systems: {list(affected_systems)[:5]}
- Confidence: {representative.confidence:.2f}
""")
        
        return "\n".join(summary_parts)
    
    def _call_bedrock_model(self, prompt: str) -> str:
        """Call AWS Bedrock model for recommendation generation."""
        try:
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 3000,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.2,  # Low temperature for consistent recommendations
                "top_p": 0.9
            }
            
            response = self.bedrock_client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(request_body),
                contentType="application/json",
                accept="application/json"
            )
            
            response_body = json.loads(response['body'].read())
            return response_body['content'][0]['text']
            
        except ClientError as e:
            logger.error(f"Bedrock API error: {str(e)}")
            raise
        except Exception as e:
            logger.error(f"Error calling Bedrock model: {str(e)}")
            raise
    
    def _parse_ai_recommendations(self, ai_response: str, threats: List[Threat]) -> List[Recommendation]:
        """Parse AI response into Recommendation objects."""
        try:
            # Extract JSON from response
            response_data = self._extract_json_from_response(ai_response)
            recommendations = []
            
            if 'recommendations' in response_data:
                for rec_data in response_data['recommendations']:
                    recommendation = self._create_recommendation_from_data(rec_data, threats)
                    if recommendation:
                        recommendations.append(recommendation)
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error parsing AI recommendations: {str(e)}")
            return []
    
    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """Extract JSON from AI response."""
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to find JSON within the response
            import re
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass
            
            logger.warning("Could not extract valid JSON from AI response")
            return {"recommendations": []}
    
    def _create_recommendation_from_data(self, rec_data: Dict[str, Any], threats: List[Threat]) -> Recommendation:
        """Create Recommendation object from parsed data."""
        try:
            # Find related threats based on threat types mentioned
            related_threats = []
            threat_types = rec_data.get('related_threat_types', [])
            for threat in threats:
                if threat.threat_type.value in threat_types:
                    related_threats.append(threat.threat_id)
            
            return Recommendation(
                recommendation_id=str(uuid.uuid4()),
                priority=rec_data.get('priority', 'medium'),
                category=rec_data.get('category', 'general'),
                title=rec_data.get('title', 'Security Recommendation'),
                description=rec_data.get('description', ''),
                implementation_steps=rec_data.get('implementation_steps', []),
                estimated_effort=rec_data.get('estimated_effort', 'unknown'),
                business_impact=rec_data.get('business_impact', ''),
                related_threats=related_threats
            )
            
        except Exception as e:
            logger.error(f"Error creating recommendation object: {str(e)}")
            return None
    
    def _deduplicate_recommendations(self, recommendations: List[Recommendation]) -> List[Recommendation]:
        """Remove duplicate recommendations based on title similarity."""
        unique_recommendations = []
        seen_titles = set()
        
        for rec in recommendations:
            # Simple deduplication based on title
            title_key = rec.title.lower().strip()
            if title_key not in seen_titles:
                seen_titles.add(title_key)
                unique_recommendations.append(rec)
        
        return unique_recommendations
    
    def _prioritize_recommendations(self, recommendations: List[Recommendation]) -> List[Recommendation]:
        """Sort recommendations by priority."""
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        
        return sorted(recommendations, 
                     key=lambda r: priority_order.get(r.priority, 4))
    
    def _estimate_effort(self, severity: ThreatSeverity) -> str:
        """Estimate effort based on threat severity."""
        if severity == ThreatSeverity.CRITICAL:
            return "immediate"
        elif severity == ThreatSeverity.HIGH:
            return "1-2 days"
        elif severity == ThreatSeverity.MEDIUM:
            return "1 week"
        else:
            return "2-4 weeks"
    
    def _assess_business_impact(self, threat: Threat) -> str:
        """Assess business impact of addressing a threat."""
        impact_descriptions = {
            ThreatSeverity.CRITICAL: "Prevents potential business disruption and data loss",
            ThreatSeverity.HIGH: "Reduces significant security risk and compliance exposure",
            ThreatSeverity.MEDIUM: "Improves overall security posture and reduces risk",
            ThreatSeverity.LOW: "Enhances security best practices and reduces minor risks"
        }
        return impact_descriptions.get(threat.severity, "Improves security posture")
    
    def _calculate_benefit_score(self, recommendation: Recommendation) -> float:
        """Calculate benefit score for cost-benefit analysis."""
        priority_scores = {'critical': 10, 'high': 7, 'medium': 5, 'low': 3}
        return priority_scores.get(recommendation.priority, 5)
    
    def _calculate_cost_score(self, recommendation: Recommendation) -> float:
        """Calculate cost score based on estimated effort."""
        effort = recommendation.estimated_effort.lower()
        if 'immediate' in effort or 'hour' in effort:
            return 1
        elif 'day' in effort:
            return 3
        elif 'week' in effort:
            return 5
        else:
            return 7
    
    def _generate_threat_specific_recommendations(self, threat: Threat) -> List[Recommendation]:
        """Generate specific recommendations for a single threat."""
        recommendations = []
        
        # Get base template
        template = self.recommendation_templates.get(threat.threat_type)
        if not template:
            return []
        
        # Create detailed recommendation
        rec = Recommendation(
            recommendation_id=str(uuid.uuid4()),
            priority=template['priority'],
            category=template['category'],
            title=f"Remediate {threat.title}",
            description=f"Comprehensive remediation for {threat.threat_type.value} threat",
            implementation_steps=self._generate_detailed_steps(threat, template['base_steps']),
            estimated_effort=self._calculate_detailed_effort(threat),
            business_impact=self._assess_detailed_business_impact(threat),
            related_threats=[threat.threat_id]
        )
        
        recommendations.append(rec)
        return recommendations
    
    def _generate_system_wide_recommendations(self, threats: List[Threat]) -> List[Recommendation]:
        """Generate system-wide security improvements based on threat patterns."""
        recommendations = []
        
        # Analyze threat patterns
        threat_types = [t.threat_type for t in threats]
        affected_systems = set()
        for t in threats:
            affected_systems.update(t.affected_systems)
        
        # Generate monitoring recommendations
        if len(threats) > 3:
            rec = Recommendation(
                recommendation_id=str(uuid.uuid4()),
                priority='high',
                category='monitoring',
                title='Enhance Security Monitoring and Detection',
                description='Implement comprehensive security monitoring to detect similar threats',
                implementation_steps=[
                    'Deploy SIEM solution or enhance existing capabilities',
                    'Configure real-time alerting for threat indicators',
                    'Implement behavioral analytics for anomaly detection',
                    'Set up automated threat hunting workflows',
                    'Create custom detection rules for identified threat patterns'
                ],
                estimated_effort='2-4 weeks',
                business_impact='Reduces mean time to detection and response for future threats',
                related_threats=[t.threat_id for t in threats]
            )
            recommendations.append(rec)
        
        # Generate access control recommendations
        if any(t.threat_type.value in ['intrusion', 'insider_threat'] for t in threats):
            rec = Recommendation(
                recommendation_id=str(uuid.uuid4()),
                priority='high',
                category='access_control',
                title='Strengthen Access Controls and Authentication',
                description='Implement zero-trust access controls to prevent unauthorized access',
                implementation_steps=[
                    'Implement multi-factor authentication (MFA) for all accounts',
                    'Deploy privileged access management (PAM) solution',
                    'Conduct access review and remove unnecessary permissions',
                    'Implement just-in-time (JIT) access for administrative functions',
                    'Enable continuous access monitoring and anomaly detection'
                ],
                estimated_effort='3-6 weeks',
                business_impact='Significantly reduces risk of unauthorized access and data breaches',
                related_threats=[t.threat_id for t in threats if t.threat_type.value in ['intrusion', 'insider_threat']]
            )
            recommendations.append(rec)
        
        return recommendations
    
    def _add_detailed_implementation_steps(self, recommendation: Recommendation, threats: List[Threat]) -> Recommendation:
        """Add detailed implementation steps to a recommendation."""
        # Enhance existing steps with more detail
        detailed_steps = []
        
        for step in recommendation.implementation_steps:
            # Add sub-steps and technical details
            if 'isolate' in step.lower():
                detailed_steps.extend([
                    f"{step}:",
                    "  - Disconnect affected systems from network",
                    "  - Preserve system state for forensic analysis", 
                    "  - Document isolation actions and timestamps",
                    "  - Notify stakeholders of system unavailability"
                ])
            elif 'patch' in step.lower():
                detailed_steps.extend([
                    f"{step}:",
                    "  - Identify all systems requiring patches",
                    "  - Test patches in non-production environment",
                    "  - Schedule maintenance window with stakeholders",
                    "  - Apply patches and verify successful installation",
                    "  - Monitor systems post-patching for issues"
                ])
            elif 'monitor' in step.lower():
                detailed_steps.extend([
                    f"{step}:",
                    "  - Define monitoring requirements and metrics",
                    "  - Configure monitoring tools and dashboards",
                    "  - Set up alerting thresholds and escalation procedures",
                    "  - Train team on new monitoring capabilities",
                    "  - Establish regular review and tuning processes"
                ])
            else:
                detailed_steps.append(step)
        
        recommendation.implementation_steps = detailed_steps
        return recommendation
    
    def _generate_detailed_steps(self, threat: Threat, base_steps: List[str]) -> List[str]:
        """Generate detailed implementation steps for a specific threat."""
        detailed_steps = []
        
        for step in base_steps:
            if threat.threat_type == ThreatType.MALWARE and 'scan' in step.lower():
                detailed_steps.extend([
                    "Perform comprehensive malware scan:",
                    "  - Run full system antimalware scan with updated signatures",
                    "  - Use multiple scanning engines for thorough detection",
                    "  - Scan all connected storage devices and network shares",
                    "  - Review scan results and quarantine detected threats",
                    "  - Document all findings and remediation actions"
                ])
            elif threat.threat_type == ThreatType.INTRUSION and 'credential' in step.lower():
                detailed_steps.extend([
                    "Reset compromised credentials:",
                    "  - Identify all potentially compromised accounts",
                    "  - Force password reset for affected users",
                    "  - Revoke and reissue API keys and certificates",
                    "  - Review and update service account credentials",
                    "  - Enable additional authentication factors"
                ])
            else:
                detailed_steps.append(step)
        
        return detailed_steps
    
    def _calculate_detailed_effort(self, threat: Threat) -> str:
        """Calculate detailed effort estimation for threat remediation."""
        base_effort = self._estimate_effort(threat.severity)
        
        # Adjust based on scope
        system_count = len(threat.affected_systems)
        if system_count > 10:
            return f"{base_effort} (extended due to {system_count} affected systems)"
        elif system_count > 5:
            return f"{base_effort} (may require additional time for {system_count} systems)"
        
        return base_effort
    
    def _assess_detailed_business_impact(self, threat: Threat) -> str:
        """Assess detailed business impact with specific metrics."""
        base_impact = self._assess_business_impact(threat)
        
        # Add specific business context
        if threat.threat_type == ThreatType.DATA_BREACH:
            return f"{base_impact}. Prevents potential regulatory fines ($10K-$1M+), customer churn (5-15%), and reputation damage."
        elif threat.threat_type == ThreatType.MALWARE:
            return f"{base_impact}. Prevents system downtime (avg $5K/hour), data corruption, and operational disruption."
        elif threat.threat_type == ThreatType.INTRUSION:
            return f"{base_impact}. Prevents unauthorized data access, intellectual property theft, and compliance violations."
        
        return base_impact
    
    def _calculate_detailed_costs(self, recommendation: Recommendation) -> Dict[str, Any]:
        """Calculate detailed cost breakdown for a recommendation."""
        # Base cost estimates (in USD)
        cost_estimates = {
            'immediate': 0,
            'implementation': 0,
            'ongoing': 0,
            'training': 0,
            'tools': 0
        }
        
        # Estimate based on category and effort
        if recommendation.category == 'incident_response':
            cost_estimates['immediate'] = 5000  # Emergency response costs
            cost_estimates['implementation'] = 2000  # Investigation and remediation
        elif recommendation.category == 'monitoring':
            cost_estimates['tools'] = 15000  # SIEM/monitoring tools (annual)
            cost_estimates['implementation'] = 10000  # Setup and configuration
            cost_estimates['training'] = 3000  # Staff training
            cost_estimates['ongoing'] = 5000  # Annual maintenance
        elif recommendation.category == 'access_control':
            cost_estimates['tools'] = 8000  # MFA/PAM tools (annual)
            cost_estimates['implementation'] = 8000  # Implementation effort
            cost_estimates['training'] = 2000  # User training
            cost_estimates['ongoing'] = 2000  # Annual maintenance
        
        # Adjust based on effort
        effort = recommendation.estimated_effort.lower()
        if 'week' in effort:
            weeks = 1
            if '2-4' in effort:
                weeks = 3
            elif '3-6' in effort:
                weeks = 4.5
            cost_estimates['implementation'] += weeks * 2000  # $2K per week labor
        
        total_first_year = sum(cost_estimates.values())
        total_ongoing = cost_estimates['ongoing'] + cost_estimates['tools']
        
        return {
            'breakdown': cost_estimates,
            'total_first_year': total_first_year,
            'total_ongoing_annual': total_ongoing,
            'currency': 'USD'
        }
    
    def _calculate_detailed_benefits(self, recommendation: Recommendation, threats: List[Threat]) -> Dict[str, Any]:
        """Calculate detailed benefit analysis for a recommendation."""
        benefits = {
            'risk_reduction': 0,
            'cost_avoidance': 0,
            'efficiency_gains': 0,
            'compliance_value': 0
        }
        
        # Calculate risk reduction value
        related_threats = [t for t in threats if t.threat_id in recommendation.related_threats]
        for threat in related_threats:
            if threat.threat_type == ThreatType.DATA_BREACH:
                benefits['risk_reduction'] += 500000  # Average data breach cost
                benefits['compliance_value'] += 100000  # Regulatory fine avoidance
            elif threat.threat_type == ThreatType.MALWARE:
                benefits['risk_reduction'] += 50000  # System recovery costs
                benefits['efficiency_gains'] += 20000  # Prevented downtime
            elif threat.threat_type == ThreatType.INTRUSION:
                benefits['risk_reduction'] += 200000  # IP theft prevention
                benefits['compliance_value'] += 50000  # Audit findings avoidance
        
        # Calculate efficiency gains
        if recommendation.category == 'monitoring':
            benefits['efficiency_gains'] += 30000  # Reduced manual investigation time
        elif recommendation.category == 'access_control':
            benefits['efficiency_gains'] += 15000  # Reduced password reset requests
        
        total_annual_benefit = sum(benefits.values())
        
        return {
            'breakdown': benefits,
            'total_annual_benefit': total_annual_benefit,
            'currency': 'USD',
            'confidence': 0.7  # 70% confidence in benefit estimates
        }
    
    def _calculate_roi_analysis(self, cost_analysis: Dict[str, Any], benefit_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate ROI analysis for a recommendation."""
        first_year_cost = cost_analysis['total_first_year']
        annual_benefit = benefit_analysis['total_annual_benefit']
        ongoing_cost = cost_analysis['total_ongoing_annual']
        
        # Calculate ROI metrics
        if first_year_cost > 0:
            first_year_roi = ((annual_benefit - first_year_cost) / first_year_cost) * 100
            payback_months = (first_year_cost / (annual_benefit / 12)) if annual_benefit > 0 else float('inf')
        else:
            first_year_roi = float('inf')
            payback_months = 0
        
        # Calculate ongoing ROI
        if ongoing_cost > 0:
            ongoing_roi = ((annual_benefit - ongoing_cost) / ongoing_cost) * 100
        else:
            ongoing_roi = float('inf')
        
        # Calculate net present value (3-year horizon, 10% discount rate)
        npv = 0
        for year in range(1, 4):
            if year == 1:
                cash_flow = annual_benefit - first_year_cost
            else:
                cash_flow = annual_benefit - ongoing_cost
            npv += cash_flow / (1.1 ** year)
        
        return {
            'first_year_roi_percent': round(first_year_roi, 1),
            'ongoing_roi_percent': round(ongoing_roi, 1),
            'payback_months': round(payback_months, 1),
            'net_present_value': round(npv, 0),
            'roi_ratio': round(annual_benefit / max(first_year_cost, 1), 2)
        }
    
    def _enhance_business_impact_with_financials(self, original_impact: str, cost_analysis: Dict[str, Any], benefit_analysis: Dict[str, Any]) -> str:
        """Enhance business impact description with financial context."""
        roi_ratio = benefit_analysis['total_annual_benefit'] / max(cost_analysis['total_first_year'], 1)
        
        financial_context = f" Investment: ${cost_analysis['total_first_year']:,}, Expected annual benefit: ${benefit_analysis['total_annual_benefit']:,}, ROI: {roi_ratio:.1f}x"
        
        return original_impact + financial_context