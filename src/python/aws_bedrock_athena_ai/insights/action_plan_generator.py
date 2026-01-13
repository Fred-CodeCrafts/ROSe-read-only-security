"""
Action plan generator for security recommendations.

This module creates prioritized action plans from security recommendations,
organizing them by priority, timeline, and business impact.
"""

import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import logging

from aws_bedrock_athena_ai.reasoning_engine.models import Recommendation, ThreatAnalysis
from aws_bedrock_athena_ai.insights.models import ActionPlan, ActionItem

logger = logging.getLogger(__name__)


class ActionPlanGenerator:
    """Generates prioritized action plans from security recommendations"""
    
    def __init__(self):
        self.effort_to_days = {
            "hours": 1,
            "1-2 days": 2,
            "days": 5,
            "1 week": 7,
            "weeks": 14,
            "1 month": 30,
            "months": 60,
            "quarter": 90
        }
        
        self.priority_weights = {
            "critical": 100,
            "high": 75,
            "medium": 50,
            "low": 25
        }
    
    def generate_prioritized_action_plan(
        self, 
        recommendations: List[Recommendation],
        analysis: Optional[ThreatAnalysis] = None
    ) -> ActionPlan:
        """
        Generate prioritized action plan from recommendations.
        
        Args:
            recommendations: List of security recommendations
            analysis: Optional threat analysis for additional context
            
        Returns:
            ActionPlan: Prioritized action plan with timeline and milestones
        """
        logger.info(f"Generating action plan from {len(recommendations)} recommendations")
        
        # Convert recommendations to action items
        action_items = self._convert_recommendations_to_actions(recommendations)
        
        # Prioritize action items
        prioritized_items = self._prioritize_action_items(action_items)
        
        # Calculate timeline and milestones
        timeline = self._calculate_implementation_timeline(prioritized_items)
        milestones = self._generate_milestones(prioritized_items)
        
        # Calculate cost estimates
        total_cost = self._calculate_total_cost_estimate(prioritized_items)
        expected_roi = self._calculate_expected_roi(prioritized_items, analysis)
        
        # Generate success metrics
        success_metrics = self._generate_success_metrics(prioritized_items, analysis)
        
        # Count items by priority
        critical_count = len([item for item in prioritized_items if item.priority == "critical"])
        high_count = len([item for item in prioritized_items if item.priority == "high"])
        
        return ActionPlan(
            plan_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            title=f"Security Improvement Action Plan - {datetime.now().strftime('%B %Y')}",
            summary=self._generate_plan_summary(prioritized_items, analysis),
            total_items=len(prioritized_items),
            critical_items=critical_count,
            high_priority_items=high_count,
            estimated_timeline=timeline,
            total_cost_estimate=total_cost,
            expected_roi=expected_roi,
            action_items=prioritized_items,
            milestones=milestones,
            success_metrics=success_metrics
        )
    
    def _convert_recommendations_to_actions(self, recommendations: List[Recommendation]) -> List[ActionItem]:
        """Convert security recommendations to actionable items"""
        action_items = []
        
        for rec in recommendations:
            # Estimate deadline based on priority and effort
            deadline = self._calculate_deadline(rec.priority, rec.estimated_effort)
            
            # Determine owner based on category
            owner = self._determine_owner(rec.category)
            
            # Generate success criteria
            success_criteria = self._generate_success_criteria(rec)
            
            # Extract cost estimate
            cost_estimate = None
            if rec.cost_analysis and 'estimated_cost' in rec.cost_analysis:
                cost_estimate = rec.cost_analysis['estimated_cost']
            
            action_item = ActionItem(
                item_id=rec.recommendation_id,
                title=rec.title,
                description=rec.description,
                priority=rec.priority,
                category=rec.category,
                owner=owner,
                estimated_effort=rec.estimated_effort,
                deadline=deadline,
                dependencies=self._identify_dependencies(rec, recommendations),
                success_criteria=success_criteria,
                business_justification=rec.business_impact,
                cost_estimate=cost_estimate
            )
            
            action_items.append(action_item)
        
        return action_items
    
    def _prioritize_action_items(self, action_items: List[ActionItem]) -> List[ActionItem]:
        """Prioritize action items based on multiple factors"""
        
        def priority_score(item: ActionItem) -> float:
            """Calculate priority score for sorting"""
            base_score = self.priority_weights.get(item.priority, 25)
            
            # Adjust for effort (prefer quick wins)
            effort_days = self._estimate_effort_days(item.estimated_effort)
            if effort_days <= 2:
                base_score += 10  # Quick win bonus
            elif effort_days >= 30:
                base_score -= 5   # Long-term penalty
            
            # Adjust for cost-effectiveness
            if item.cost_estimate:
                if item.cost_estimate < 1000:  # Low cost bonus
                    base_score += 5
                elif item.cost_estimate > 10000:  # High cost penalty
                    base_score -= 10
            
            # Adjust for dependencies (items with no dependencies get priority)
            if not item.dependencies:
                base_score += 5
            
            return base_score
        
        # Sort by priority score (highest first)
        return sorted(action_items, key=priority_score, reverse=True)
    
    def _calculate_implementation_timeline(self, action_items: List[ActionItem]) -> str:
        """Calculate overall implementation timeline"""
        if not action_items:
            return "No actions required"
        
        # Calculate parallel and sequential work
        critical_items = [item for item in action_items if item.priority == "critical"]
        high_items = [item for item in action_items if item.priority == "high"]
        
        critical_days = sum(self._estimate_effort_days(item.estimated_effort) for item in critical_items)
        high_days = sum(self._estimate_effort_days(item.estimated_effort) for item in high_items)
        
        # Assume some parallelization
        total_days = max(critical_days, high_days * 0.7)  # 30% parallelization for high priority
        
        if total_days <= 30:
            return "1 month"
        elif total_days <= 90:
            return "1-3 months"
        elif total_days <= 180:
            return "3-6 months"
        else:
            return "6+ months"
    
    def _generate_milestones(self, action_items: List[ActionItem]) -> List[Dict[str, Any]]:
        """Generate implementation milestones"""
        milestones = []
        
        # Critical items milestone
        critical_items = [item for item in action_items if item.priority == "critical"]
        if critical_items:
            milestones.append({
                "name": "Critical Security Issues Resolved",
                "description": f"Complete {len(critical_items)} critical security improvements",
                "target_date": (datetime.now() + timedelta(days=30)).isoformat(),
                "success_criteria": [
                    "All critical vulnerabilities patched",
                    "Immediate security risks mitigated",
                    "Security monitoring enhanced"
                ],
                "deliverables": [item.title for item in critical_items[:3]]
            })
        
        # High priority milestone
        high_items = [item for item in action_items if item.priority == "high"]
        if high_items:
            milestones.append({
                "name": "Security Posture Enhancement",
                "description": f"Implement {len(high_items)} high-priority security improvements",
                "target_date": (datetime.now() + timedelta(days=90)).isoformat(),
                "success_criteria": [
                    "Security controls strengthened",
                    "Compliance gaps addressed",
                    "Risk exposure reduced"
                ],
                "deliverables": [item.title for item in high_items[:3]]
            })
        
        # Overall completion milestone
        milestones.append({
            "name": "Security Program Maturity",
            "description": "Complete comprehensive security improvement program",
            "target_date": (datetime.now() + timedelta(days=180)).isoformat(),
            "success_criteria": [
                "All identified security gaps addressed",
                "Continuous monitoring established",
                "Security metrics improved by 50%"
            ],
            "deliverables": [
                "Complete security assessment",
                "Updated security policies",
                "Enhanced incident response capabilities"
            ]
        })
        
        return milestones
    
    def _calculate_total_cost_estimate(self, action_items: List[ActionItem]) -> Optional[float]:
        """Calculate total cost estimate for all action items"""
        total_cost = 0
        items_with_cost = 0
        
        for item in action_items:
            if item.cost_estimate:
                total_cost += item.cost_estimate
                items_with_cost += 1
        
        if items_with_cost == 0:
            return None
        
        # If not all items have cost estimates, extrapolate
        if items_with_cost < len(action_items):
            avg_cost = total_cost / items_with_cost
            estimated_total = avg_cost * len(action_items)
            return estimated_total
        
        return total_cost
    
    def _calculate_expected_roi(
        self, 
        action_items: List[ActionItem], 
        analysis: Optional[ThreatAnalysis]
    ) -> Optional[float]:
        """Calculate expected ROI from security improvements"""
        if not analysis:
            return None
        
        # Estimate risk reduction value
        current_risk_score = analysis.risk_assessment.overall_risk_score
        
        # Estimate risk reduction from implementing recommendations
        critical_items = len([item for item in action_items if item.priority == "critical"])
        high_items = len([item for item in action_items if item.priority == "high"])
        
        # Risk reduction estimate (simplified model)
        risk_reduction = min(0.7, (critical_items * 0.2) + (high_items * 0.1))
        
        # Estimate cost of security incidents (industry average)
        avg_incident_cost = 4450000  # $4.45M average data breach cost
        incident_probability = current_risk_score / 10.0  # Risk score as probability
        
        # Calculate expected savings
        expected_annual_savings = avg_incident_cost * incident_probability * risk_reduction
        
        # Calculate total investment
        total_cost = self._calculate_total_cost_estimate(action_items)
        if not total_cost or total_cost == 0:
            return None
        
        # ROI calculation (3-year horizon)
        three_year_savings = expected_annual_savings * 3
        roi = (three_year_savings - total_cost) / total_cost
        
        return max(0, roi)  # Don't return negative ROI
    
    def _generate_success_metrics(
        self, 
        action_items: List[ActionItem], 
        analysis: Optional[ThreatAnalysis]
    ) -> List[str]:
        """Generate success metrics for the action plan"""
        metrics = []
        
        # Risk reduction metrics
        if analysis:
            current_risk = analysis.risk_assessment.overall_risk_score
            target_risk = max(2.0, current_risk - 2.0)
            metrics.append(f"Reduce overall risk score from {current_risk:.1f} to {target_risk:.1f}")
        
        # Threat mitigation metrics
        critical_count = len([item for item in action_items if item.priority == "critical"])
        if critical_count > 0:
            metrics.append(f"Resolve 100% of {critical_count} critical security issues")
        
        # Coverage metrics
        metrics.append("Achieve 90%+ security control coverage")
        metrics.append("Reduce mean time to detection (MTTD) by 50%")
        metrics.append("Improve incident response time by 40%")
        
        # Compliance metrics
        metrics.append("Achieve 95%+ compliance score across all frameworks")
        
        # Operational metrics
        metrics.append("Establish 24/7 security monitoring capabilities")
        metrics.append("Implement automated threat detection and response")
        
        return metrics
    
    def _generate_plan_summary(
        self, 
        action_items: List[ActionItem], 
        analysis: Optional[ThreatAnalysis]
    ) -> str:
        """Generate executive summary of the action plan"""
        critical_count = len([item for item in action_items if item.priority == "critical"])
        high_count = len([item for item in action_items if item.priority == "high"])
        
        summary = f"""
        Comprehensive security improvement plan addressing {len(action_items)} identified areas for enhancement.
        
        Immediate priorities include {critical_count} critical security issues requiring urgent attention.
        Strategic improvements encompass {high_count} high-priority initiatives to strengthen overall security posture.
        
        Implementation follows a phased approach prioritizing risk reduction and business continuity.
        Expected outcomes include significant risk reduction, improved compliance, and enhanced security capabilities.
        """
        
        if analysis:
            current_risk = analysis.risk_assessment.overall_risk_score
            summary += f"\nCurrent risk level: {current_risk:.1f}/10.0. Target: Reduce to {max(2.0, current_risk - 2.0):.1f}/10.0"
        
        return summary.strip()
    
    # Helper methods
    def _calculate_deadline(self, priority: str, estimated_effort: str) -> Optional[datetime]:
        """Calculate deadline based on priority and effort"""
        base_days = self._estimate_effort_days(estimated_effort)
        
        # Adjust based on priority
        if priority == "critical":
            deadline_days = min(30, base_days + 7)  # Max 30 days for critical
        elif priority == "high":
            deadline_days = min(90, base_days + 14)  # Max 90 days for high
        elif priority == "medium":
            deadline_days = min(180, base_days + 30)  # Max 180 days for medium
        else:
            deadline_days = base_days + 60  # Low priority gets extra time
        
        return datetime.now() + timedelta(days=deadline_days)
    
    def _estimate_effort_days(self, estimated_effort: str) -> int:
        """Convert effort estimate to days"""
        effort_lower = estimated_effort.lower()
        
        for key, days in self.effort_to_days.items():
            if key in effort_lower:
                return days
        
        # Default fallback
        return 7
    
    def _determine_owner(self, category: str) -> str:
        """Determine owner based on recommendation category"""
        category_owners = {
            "infrastructure": "Infrastructure Team",
            "network": "Network Security Team",
            "application": "Application Security Team",
            "compliance": "Compliance Team",
            "incident_response": "Security Operations Team",
            "access_control": "Identity and Access Management Team",
            "monitoring": "Security Operations Center",
            "training": "Security Awareness Team",
            "policy": "Security Governance Team"
        }
        
        return category_owners.get(category.lower(), "Security Team")
    
    def _generate_success_criteria(self, recommendation: Recommendation) -> List[str]:
        """Generate success criteria for a recommendation"""
        criteria = []
        
        # Generic success criteria based on category
        if "vulnerability" in recommendation.category.lower():
            criteria.append("Vulnerability successfully patched or mitigated")
            criteria.append("No remaining exploitable attack vectors")
        
        if "monitoring" in recommendation.category.lower():
            criteria.append("Monitoring system deployed and operational")
            criteria.append("Alerts configured and tested")
        
        if "access" in recommendation.category.lower():
            criteria.append("Access controls implemented and verified")
            criteria.append("User permissions validated")
        
        # Add threat-specific criteria
        if recommendation.related_threats:
            criteria.append(f"Mitigation verified for {len(recommendation.related_threats)} related threats")
        
        # Add compliance criteria
        if recommendation.compliance_frameworks:
            criteria.append(f"Compliance validated for {', '.join(recommendation.compliance_frameworks)}")
        
        # Default criteria if none specific
        if not criteria:
            criteria = [
                "Implementation completed successfully",
                "Security improvement verified through testing",
                "No negative impact on business operations"
            ]
        
        return criteria
    
    def _identify_dependencies(
        self, 
        recommendation: Recommendation, 
        all_recommendations: List[Recommendation]
    ) -> List[str]:
        """Identify dependencies between recommendations"""
        dependencies = []
        
        # Simple dependency detection based on categories and related threats
        for other_rec in all_recommendations:
            if other_rec.recommendation_id == recommendation.recommendation_id:
                continue
            
            # Check for shared threats (dependency indicator)
            shared_threats = set(recommendation.related_threats) & set(other_rec.related_threats)
            if shared_threats and other_rec.priority in ["critical", "high"]:
                dependencies.append(other_rec.recommendation_id)
            
            # Check for category dependencies
            if self._has_category_dependency(recommendation.category, other_rec.category):
                dependencies.append(other_rec.recommendation_id)
        
        return dependencies[:3]  # Limit to 3 dependencies for simplicity
    
    def _has_category_dependency(self, category1: str, category2: str) -> bool:
        """Check if one category depends on another"""
        dependencies = {
            "application": ["infrastructure", "network"],
            "monitoring": ["infrastructure"],
            "incident_response": ["monitoring"],
            "compliance": ["access_control", "monitoring"]
        }
        
        return category2.lower() in dependencies.get(category1.lower(), [])