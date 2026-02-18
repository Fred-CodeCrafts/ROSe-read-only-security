"""
Interactive tutorial system for learning the AI Security Analyst.

This module provides guided tutorials that teach users how to effectively
use the system through hands-on examples and real security scenarios.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from aws_bedrock_athena_ai.onboarding.models import Tutorial, TutorialStep, TutorialType, OnboardingSession

logger = logging.getLogger(__name__)


class TutorialSystem:
    """Manages interactive tutorials for learning the AI Security Analyst"""
    
    def __init__(self):
        self.available_tutorials = self._create_tutorial_catalog()
    
    def _create_tutorial_catalog(self) -> Dict[str, Tutorial]:
        """Create the catalog of available tutorials"""
        tutorials = {}
        
        # Basic Questions Tutorial
        basic_tutorial = Tutorial(
            tutorial_id="basic_questions",
            title="Ask Your First Security Questions",
            description="Learn how to ask effective security questions in natural language",
            tutorial_type=TutorialType.BASIC_QUESTIONS,
            estimated_duration_minutes=10,
            difficulty_level="beginner",
            steps=[
                TutorialStep(
                    step_id="basic_1",
                    title="Ask About Current Threats",
                    description="Learn to ask about immediate security concerns",
                    example_question="Are we being attacked right now?",
                    expected_outcome="Get real-time threat assessment with specific findings",
                    hints=[
                        "Use present tense for current status questions",
                        "Be specific about timeframes when needed",
                        "Ask follow-up questions for more details"
                    ]
                ),
                TutorialStep(
                    step_id="basic_2", 
                    title="Check Recent Activity",
                    description="Learn to investigate recent security events",
                    example_question="Show me failed login attempts from last week",
                    expected_outcome="Get detailed analysis of authentication failures",
                    hints=[
                        "Specify time ranges for historical analysis",
                        "Ask about specific event types",
                        "Request details about patterns or trends"
                    ]
                ),
                TutorialStep(
                    step_id="basic_3",
                    title="Assess Overall Security",
                    description="Learn to get high-level security assessments",
                    example_question="What's our biggest security risk?",
                    expected_outcome="Get prioritized risk assessment with recommendations",
                    hints=[
                        "Ask open-ended questions for comprehensive analysis",
                        "Request business impact information",
                        "Ask for specific remediation steps"
                    ]
                )
            ]
        )
        tutorials[basic_tutorial.tutorial_id] = basic_tutorial
        
        # Threat Hunting Tutorial
        threat_tutorial = Tutorial(
            tutorial_id="threat_hunting",
            title="Advanced Threat Hunting",
            description="Learn to proactively hunt for sophisticated threats",
            tutorial_type=TutorialType.THREAT_HUNTING,
            estimated_duration_minutes=20,
            difficulty_level="intermediate",
            steps=[
                TutorialStep(
                    step_id="threat_1",
                    title="Hunt for Lateral Movement",
                    description="Detect attackers moving through your network",
                    example_question="Show me unusual network connections between internal systems",
                    expected_outcome="Identify potential lateral movement patterns",
                    hints=[
                        "Look for connections between systems that don't normally communicate",
                        "Focus on administrative protocols (RDP, SSH, WMI)",
                        "Check for connections outside normal business hours"
                    ]
                ),
                TutorialStep(
                    step_id="threat_2",
                    title="Detect Privilege Escalation",
                    description="Find attempts to gain higher privileges",
                    example_question="Find users who gained new permissions recently",
                    expected_outcome="Identify suspicious privilege changes",
                    hints=[
                        "Look for rapid permission changes",
                        "Check for service account abuse",
                        "Monitor administrative group modifications"
                    ]
                ),
                TutorialStep(
                    step_id="threat_3",
                    title="Identify Data Exfiltration",
                    description="Detect potential data theft attempts",
                    example_question="Show me large file transfers to external locations",
                    expected_outcome="Find suspicious data movement patterns",
                    hints=[
                        "Look for unusual data volumes",
                        "Check transfers to unknown external IPs",
                        "Monitor after-hours data access"
                    ]
                )
            ]
        )
        tutorials[threat_tutorial.tutorial_id] = threat_tutorial
        
        # Compliance Check Tutorial
        compliance_tutorial = Tutorial(
            tutorial_id="compliance_check",
            title="Security Compliance Assessment",
            description="Learn to assess and monitor compliance with security frameworks",
            tutorial_type=TutorialType.COMPLIANCE_CHECK,
            estimated_duration_minutes=15,
            difficulty_level="intermediate",
            steps=[
                TutorialStep(
                    step_id="compliance_1",
                    title="Check Access Controls",
                    description="Assess user access and permissions compliance",
                    example_question="Are our access controls compliant with SOX requirements?",
                    expected_outcome="Get detailed compliance assessment with gaps identified",
                    hints=[
                        "Ask about specific compliance frameworks",
                        "Request gap analysis and remediation steps",
                        "Check for segregation of duties violations"
                    ]
                ),
                TutorialStep(
                    step_id="compliance_2",
                    title="Audit Logging Review",
                    description="Verify audit logging meets compliance requirements",
                    example_question="Is our audit logging sufficient for PCI DSS compliance?",
                    expected_outcome="Assessment of logging coverage and quality",
                    hints=[
                        "Check for complete audit trails",
                        "Verify log retention periods",
                        "Ensure critical events are logged"
                    ]
                ),
                TutorialStep(
                    step_id="compliance_3",
                    title="Password Policy Assessment",
                    description="Review password policies and enforcement",
                    example_question="Do our password policies meet industry standards?",
                    expected_outcome="Analysis of password policy compliance",
                    hints=[
                        "Check password complexity requirements",
                        "Verify password rotation policies",
                        "Look for weak or default passwords"
                    ]
                )
            ]
        )
        tutorials[compliance_tutorial.tutorial_id] = compliance_tutorial
        
        # Risk Assessment Tutorial
        risk_tutorial = Tutorial(
            tutorial_id="risk_assessment",
            title="Comprehensive Risk Assessment",
            description="Learn to perform thorough security risk assessments",
            tutorial_type=TutorialType.RISK_ASSESSMENT,
            estimated_duration_minutes=25,
            difficulty_level="advanced",
            steps=[
                TutorialStep(
                    step_id="risk_1",
                    title="Identify Critical Assets",
                    description="Find and prioritize your most important systems",
                    example_question="What are our most critical systems and their risk levels?",
                    expected_outcome="Prioritized list of critical assets with risk scores",
                    hints=[
                        "Consider business impact of system compromise",
                        "Look at data sensitivity levels",
                        "Assess system interconnections"
                    ]
                ),
                TutorialStep(
                    step_id="risk_2",
                    title="Vulnerability Assessment",
                    description="Identify and prioritize security vulnerabilities",
                    example_question="Show me our highest priority vulnerabilities",
                    expected_outcome="Risk-ranked vulnerability list with remediation guidance",
                    hints=[
                        "Focus on exploitable vulnerabilities",
                        "Consider CVSS scores and exploit availability",
                        "Prioritize by business impact"
                    ]
                ),
                TutorialStep(
                    step_id="risk_3",
                    title="Business Impact Analysis",
                    description="Understand the business impact of security risks",
                    example_question="What would be the business impact if our database was compromised?",
                    expected_outcome="Detailed business impact assessment with cost estimates",
                    hints=[
                        "Consider direct and indirect costs",
                        "Include regulatory and reputational impacts",
                        "Estimate recovery time and costs"
                    ]
                )
            ]
        )
        tutorials[risk_tutorial.tutorial_id] = risk_tutorial
        
        # Incident Response Tutorial
        incident_tutorial = Tutorial(
            tutorial_id="incident_response",
            title="Security Incident Response",
            description="Learn to investigate and respond to security incidents",
            tutorial_type=TutorialType.INCIDENT_RESPONSE,
            estimated_duration_minutes=30,
            difficulty_level="advanced",
            steps=[
                TutorialStep(
                    step_id="incident_1",
                    title="Initial Incident Triage",
                    description="Quickly assess and prioritize security incidents",
                    example_question="I suspect we have a security breach - help me investigate",
                    expected_outcome="Structured incident assessment with immediate actions",
                    hints=[
                        "Gather initial indicators of compromise",
                        "Assess scope and severity quickly",
                        "Identify immediate containment actions"
                    ]
                ),
                TutorialStep(
                    step_id="incident_2",
                    title="Timeline Reconstruction",
                    description="Build a timeline of the security incident",
                    example_question="Show me the timeline of events for this suspected breach",
                    expected_outcome="Detailed chronological timeline of incident events",
                    hints=[
                        "Correlate events across multiple systems",
                        "Look for initial compromise indicators",
                        "Track attacker progression through systems"
                    ]
                ),
                TutorialStep(
                    step_id="incident_3",
                    title="Impact Assessment and Recovery",
                    description="Assess damage and plan recovery actions",
                    example_question="What systems were affected and how do we recover?",
                    expected_outcome="Comprehensive impact assessment with recovery plan",
                    hints=[
                        "Identify all affected systems and data",
                        "Assess data integrity and confidentiality",
                        "Plan systematic recovery and hardening"
                    ]
                )
            ]
        )
        tutorials[incident_tutorial.tutorial_id] = incident_tutorial
        
        return tutorials
    
    def get_available_tutorials(self, difficulty_level: Optional[str] = None) -> List[Tutorial]:
        """Get list of available tutorials, optionally filtered by difficulty"""
        tutorials = list(self.available_tutorials.values())
        
        if difficulty_level:
            tutorials = [t for t in tutorials if t.difficulty_level == difficulty_level]
        
        return sorted(tutorials, key=lambda t: t.estimated_duration_minutes)
    
    def start_tutorial(self, tutorial_id: str, session: OnboardingSession) -> Tutorial:
        """Start a tutorial for the user"""
        if tutorial_id not in self.available_tutorials:
            raise ValueError(f"Tutorial not found: {tutorial_id}")
        
        tutorial = self.available_tutorials[tutorial_id]
        tutorial.started_at = datetime.now()
        tutorial.completion_percentage = 0.0
        
        # Reset all steps
        for step in tutorial.steps:
            step.completed = False
        
        session.active_tutorial = tutorial
        logger.info(f"🎓 Started tutorial: {tutorial.title}")
        
        return tutorial
    
    def complete_tutorial_step(self, tutorial_id: str, step_id: str, 
                             session: OnboardingSession) -> Dict[str, Any]:
        """Mark a tutorial step as completed"""
        if not session.active_tutorial or session.active_tutorial.tutorial_id != tutorial_id:
            raise ValueError("Tutorial not active or mismatch")
        
        tutorial = session.active_tutorial
        
        # Find and complete the step
        step_found = False
        for step in tutorial.steps:
            if step.step_id == step_id:
                step.completed = True
                step_found = True
                break
        
        if not step_found:
            raise ValueError(f"Tutorial step not found: {step_id}")
        
        # Update completion percentage
        completed_steps = sum(1 for step in tutorial.steps if step.completed)
        tutorial.completion_percentage = (completed_steps / len(tutorial.steps)) * 100
        
        # Check if tutorial is complete
        if tutorial.completion_percentage >= 100:
            tutorial.completed_at = datetime.now()
            session.progress.completed_tutorials.append(tutorial_id)
            logger.info(f"🎉 Tutorial completed: {tutorial.title}")
        
        return {
            "step_completed": step_id,
            "tutorial_progress": tutorial.completion_percentage,
            "tutorial_complete": tutorial.completion_percentage >= 100,
            "next_step": self._get_next_step(tutorial)
        }
    
    def _get_next_step(self, tutorial: Tutorial) -> Optional[Dict[str, Any]]:
        """Get the next uncompleted step in the tutorial"""
        for step in tutorial.steps:
            if not step.completed:
                return {
                    "step_id": step.step_id,
                    "title": step.title,
                    "description": step.description,
                    "example_question": step.example_question,
                    "hints": step.hints
                }
        return None
    
    def get_tutorial_progress(self, tutorial_id: str, session: OnboardingSession) -> Dict[str, Any]:
        """Get current progress for a tutorial"""
        if not session.active_tutorial or session.active_tutorial.tutorial_id != tutorial_id:
            if tutorial_id in session.progress.completed_tutorials:
                return {
                    "tutorial_id": tutorial_id,
                    "status": "completed",
                    "completion_percentage": 100.0,
                    "completed_at": "Previously completed"
                }
            else:
                return {
                    "tutorial_id": tutorial_id,
                    "status": "not_started",
                    "completion_percentage": 0.0
                }
        
        tutorial = session.active_tutorial
        return {
            "tutorial_id": tutorial_id,
            "status": "in_progress",
            "completion_percentage": tutorial.completion_percentage,
            "started_at": tutorial.started_at.isoformat() if tutorial.started_at else None,
            "current_step": self._get_next_step(tutorial),
            "completed_steps": [step.step_id for step in tutorial.steps if step.completed],
            "total_steps": len(tutorial.steps)
        }
    
    def get_tutorial_recommendations(self, session: OnboardingSession) -> List[Dict[str, Any]]:
        """Get personalized tutorial recommendations based on user progress"""
        recommendations = []
        
        # Always recommend basic questions first
        if "basic_questions" not in session.progress.completed_tutorials:
            recommendations.append({
                "tutorial_id": "basic_questions",
                "title": "Ask Your First Security Questions",
                "priority": "high",
                "reason": "Essential foundation for using the AI Security Analyst",
                "estimated_minutes": 10
            })
        
        # Recommend based on uploaded data types
        has_network_data = any(
            "network" in f.original_filename.lower() or 
            "vpc" in f.original_filename.lower() or
            "flow" in f.original_filename.lower()
            for f in session.progress.uploaded_files
        )
        
        has_auth_data = any(
            "auth" in f.original_filename.lower() or
            "login" in f.original_filename.lower() or
            "cloudtrail" in f.original_filename.lower()
            for f in session.progress.uploaded_files
        )
        
        if has_network_data and "threat_hunting" not in session.progress.completed_tutorials:
            recommendations.append({
                "tutorial_id": "threat_hunting",
                "title": "Advanced Threat Hunting",
                "priority": "medium",
                "reason": "You have network data perfect for threat hunting exercises",
                "estimated_minutes": 20
            })
        
        if has_auth_data and "incident_response" not in session.progress.completed_tutorials:
            recommendations.append({
                "tutorial_id": "incident_response",
                "title": "Security Incident Response",
                "priority": "medium", 
                "reason": "Your authentication data is ideal for incident response scenarios",
                "estimated_minutes": 30
            })
        
        # Always offer compliance and risk assessment
        if "compliance_check" not in session.progress.completed_tutorials:
            recommendations.append({
                "tutorial_id": "compliance_check",
                "title": "Security Compliance Assessment",
                "priority": "low",
                "reason": "Learn to assess compliance with security frameworks",
                "estimated_minutes": 15
            })
        
        if "risk_assessment" not in session.progress.completed_tutorials:
            recommendations.append({
                "tutorial_id": "risk_assessment",
                "title": "Comprehensive Risk Assessment",
                "priority": "low",
                "reason": "Master advanced risk assessment techniques",
                "estimated_minutes": 25
            })
        
        return recommendations
    
    def generate_tutorial_certificate(self, tutorial_id: str, session: OnboardingSession) -> Dict[str, Any]:
        """Generate a completion certificate for a tutorial"""
        if tutorial_id not in session.progress.completed_tutorials:
            raise ValueError("Tutorial not completed")
        
        tutorial = self.available_tutorials[tutorial_id]
        
        return {
            "certificate_id": f"cert_{session.progress.user_id}_{tutorial_id}_{int(datetime.now().timestamp())}",
            "user_id": session.progress.user_id,
            "tutorial_title": tutorial.title,
            "tutorial_type": tutorial.tutorial_type.value,
            "difficulty_level": tutorial.difficulty_level,
            "completion_date": datetime.now().isoformat(),
            "skills_learned": [
                step.title for step in tutorial.steps
            ],
            "certificate_text": f"This certifies that {session.progress.user_id} has successfully completed the '{tutorial.title}' tutorial for the AI Security Analyst system, demonstrating proficiency in {tutorial.tutorial_type.value.replace('_', ' ')} techniques."
        }