"""
Pre-built demonstration scenarios for showcasing AI Security Analyst capabilities.

This module provides realistic security scenarios with sample data and expected
outcomes to demonstrate the system's value immediately.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from aws_bedrock_athena_ai.onboarding.models import DemoScenario, OnboardingSession
from aws_bedrock_athena_ai.onboarding.sample_data import SampleDataGenerator

logger = logging.getLogger(__name__)


class DemoScenarios:
    """Manages pre-built demonstration scenarios for immediate value demonstration"""
    
    def __init__(self):
        self.sample_generator = SampleDataGenerator()
        self.available_scenarios = self._create_scenario_catalog()
    
    def _create_scenario_catalog(self) -> Dict[str, DemoScenario]:
        """Create catalog of available demonstration scenarios"""
        scenarios = {}
        
        # Breach Detection Scenario
        breach_scenario = DemoScenario(
            scenario_id="breach_detection",
            title="Detecting a Live Security Breach",
            description="Experience how the AI detects and analyzes an active security breach with real-time threat intelligence",
            scenario_type="breach_detection",
            sample_data_included=True,
            key_questions=[
                "Are we being attacked right now?",
                "Show me the attack timeline",
                "What systems are compromised?",
                "How do we stop this attack?",
                "What's the business impact?"
            ],
            expected_insights=[
                "Active brute force attack detected from external IP",
                "Lateral movement across 3 internal systems identified",
                "Administrative credentials potentially compromised",
                "Immediate containment actions recommended",
                "Estimated business impact: $2.3M if not contained"
            ],
            business_value="Demonstrates how AI can detect sophisticated attacks in real-time, potentially saving millions in breach costs",
            estimated_duration_minutes=15
        )
        scenarios[breach_scenario.scenario_id] = breach_scenario
        
        # Compliance Audit Scenario
        compliance_scenario = DemoScenario(
            scenario_id="compliance_audit",
            title="Instant SOX Compliance Assessment",
            description="See how the AI performs a comprehensive SOX compliance audit in minutes instead of weeks",
            scenario_type="compliance_audit",
            sample_data_included=True,
            key_questions=[
                "Are we compliant with SOX requirements?",
                "What compliance gaps do we have?",
                "Show me access control violations",
                "Generate a compliance report for auditors",
                "What's our compliance score?"
            ],
            expected_insights=[
                "94% SOX compliance achieved",
                "3 critical access control gaps identified",
                "Audit logging missing on 2 systems",
                "Segregation of duties violations found",
                "Remediation plan with cost estimates provided"
            ],
            business_value="Reduces compliance audit time from weeks to minutes, ensuring continuous compliance and avoiding penalties",
            estimated_duration_minutes=12
        )
        scenarios[compliance_scenario.scenario_id] = compliance_scenario
        
        # Risk Assessment Scenario
        risk_scenario = DemoScenario(
            scenario_id="risk_assessment",
            title="Executive Risk Dashboard in 5 Minutes",
            description="Watch the AI create an executive-level risk assessment with business impact analysis",
            scenario_type="risk_assessment",
            sample_data_included=True,
            key_questions=[
                "What's our biggest security risk?",
                "Show me our risk dashboard",
                "What would a breach cost us?",
                "Prioritize our security investments",
                "Compare us to industry benchmarks"
            ],
            expected_insights=[
                "Unpatched vulnerabilities pose highest risk",
                "12 critical systems need immediate attention",
                "Potential breach cost: $4.5M average",
                "ROI analysis for security investments",
                "Below industry average in 2 key areas"
            ],
            business_value="Provides executives with clear, business-focused security insights for informed decision making",
            estimated_duration_minutes=10
        )
        scenarios[risk_scenario.scenario_id] = risk_scenario
        
        # Insider Threat Scenario
        insider_scenario = DemoScenario(
            scenario_id="insider_threat",
            title="Detecting Insider Threats with Behavioral Analysis",
            description="Experience how AI detects subtle insider threats through behavioral pattern analysis",
            scenario_type="insider_threat",
            sample_data_included=True,
            key_questions=[
                "Are there any insider threats?",
                "Show me unusual user behavior",
                "Who accessed sensitive data recently?",
                "Find users with suspicious activity patterns",
                "What data might be at risk?"
            ],
            expected_insights=[
                "Unusual after-hours access by 2 employees",
                "Large data downloads outside normal patterns",
                "Access to systems beyond job requirements",
                "Behavioral anomalies suggest potential insider risk",
                "Recommended monitoring and investigation steps"
            ],
            business_value="Detects insider threats that traditional security tools miss, protecting against data theft and sabotage",
            estimated_duration_minutes=18
        )
        scenarios[insider_scenario.scenario_id] = insider_scenario
        
        # Cloud Security Scenario
        cloud_scenario = DemoScenario(
            scenario_id="cloud_security",
            title="AWS Cloud Security Posture Assessment",
            description="See how the AI analyzes your entire AWS environment for security misconfigurations and threats",
            scenario_type="cloud_security",
            sample_data_included=True,
            key_questions=[
                "How secure is our AWS environment?",
                "Show me cloud misconfigurations",
                "Are our S3 buckets secure?",
                "Find overprivileged IAM users",
                "What's our cloud security score?"
            ],
            expected_insights=[
                "3 publicly accessible S3 buckets found",
                "12 overprivileged IAM users identified",
                "Security groups with overly broad access",
                "CloudTrail logging gaps in 2 regions",
                "Overall cloud security score: 78/100"
            ],
            business_value="Ensures cloud infrastructure security, preventing data breaches and compliance violations",
            estimated_duration_minutes=14
        )
        scenarios[cloud_scenario.scenario_id] = cloud_scenario
        
        # Incident Response Scenario
        incident_scenario = DemoScenario(
            scenario_id="incident_response",
            title="Rapid Incident Response and Forensics",
            description="Experience AI-powered incident response that reconstructs attack timelines and guides remediation",
            scenario_type="incident_response",
            sample_data_included=True,
            key_questions=[
                "Help me investigate this security incident",
                "Show me the attack timeline",
                "What was the initial compromise?",
                "How far did the attacker get?",
                "What's our recovery plan?"
            ],
            expected_insights=[
                "Initial compromise via phishing email",
                "Lateral movement timeline reconstructed",
                "3 systems compromised, 1 with data access",
                "No evidence of data exfiltration",
                "Step-by-step recovery and hardening plan"
            ],
            business_value="Accelerates incident response from days to hours, minimizing damage and recovery costs",
            estimated_duration_minutes=20
        )
        scenarios[incident_scenario.scenario_id] = incident_scenario
        
        return scenarios
    
    def get_available_scenarios(self, scenario_type: Optional[str] = None) -> List[DemoScenario]:
        """Get list of available scenarios, optionally filtered by type"""
        scenarios = list(self.available_scenarios.values())
        
        if scenario_type:
            scenarios = [s for s in scenarios if s.scenario_type == scenario_type]
        
        return sorted(scenarios, key=lambda s: s.estimated_duration_minutes)
    
    def start_scenario(self, scenario_id: str, session: OnboardingSession) -> Dict[str, Any]:
        """Start a demonstration scenario"""
        if scenario_id not in self.available_scenarios:
            raise ValueError(f"Scenario not found: {scenario_id}")
        
        scenario = self.available_scenarios[scenario_id]
        
        # Generate sample data for the scenario
        sample_data = self._generate_scenario_data(scenario)
        
        # Create scenario context
        scenario_context = {
            "scenario_id": scenario_id,
            "title": scenario.title,
            "description": scenario.description,
            "started_at": datetime.now().isoformat(),
            "sample_data": sample_data,
            "key_questions": scenario.key_questions,
            "expected_insights": scenario.expected_insights,
            "business_value": scenario.business_value,
            "current_step": 0,
            "total_steps": len(scenario.key_questions),
            "progress_percentage": 0.0
        }
        
        logger.info(f"🎬 Started demo scenario: {scenario.title}")
        return scenario_context
    
    def _generate_scenario_data(self, scenario: DemoScenario) -> Dict[str, Any]:
        """Generate realistic sample data for a specific scenario"""
        if scenario.scenario_type == "breach_detection":
            return self._generate_breach_data()
        elif scenario.scenario_type == "compliance_audit":
            return self._generate_compliance_data()
        elif scenario.scenario_type == "risk_assessment":
            return self._generate_risk_data()
        elif scenario.scenario_type == "insider_threat":
            return self._generate_insider_threat_data()
        elif scenario.scenario_type == "cloud_security":
            return self._generate_cloud_security_data()
        elif scenario.scenario_type == "incident_response":
            return self._generate_incident_data()
        else:
            return self._generate_generic_security_data()
    
    def _generate_breach_data(self) -> Dict[str, Any]:
        """Generate data for breach detection scenario"""
        return {
            "attack_timeline": [
                {
                    "timestamp": (datetime.now() - timedelta(hours=4)).isoformat(),
                    "event": "Initial reconnaissance from 203.0.113.50",
                    "severity": "medium"
                },
                {
                    "timestamp": (datetime.now() - timedelta(hours=3)).isoformat(),
                    "event": "Brute force attack against admin accounts",
                    "severity": "high"
                },
                {
                    "timestamp": (datetime.now() - timedelta(hours=2)).isoformat(),
                    "event": "Successful login as 'admin' from external IP",
                    "severity": "critical"
                },
                {
                    "timestamp": (datetime.now() - timedelta(hours=1)).isoformat(),
                    "event": "Lateral movement to database server",
                    "severity": "critical"
                },
                {
                    "timestamp": (datetime.now() - timedelta(minutes=30)).isoformat(),
                    "event": "Suspicious database queries detected",
                    "severity": "critical"
                }
            ],
            "compromised_systems": [
                "web-server-01",
                "app-server-01", 
                "db-server-01"
            ],
            "attack_indicators": [
                "Multiple failed logins from 203.0.113.50",
                "Successful admin login from external IP",
                "Unusual database access patterns",
                "Large data queries outside business hours"
            ],
            "business_impact": {
                "estimated_cost": 2300000,
                "affected_customers": 15000,
                "downtime_hours": 0,
                "data_at_risk": "Customer PII and payment data"
            }
        }
    
    def _generate_compliance_data(self) -> Dict[str, Any]:
        """Generate data for compliance audit scenario"""
        return {
            "compliance_frameworks": ["SOX", "PCI DSS", "ISO 27001"],
            "overall_score": 94,
            "compliance_status": {
                "access_controls": {
                    "score": 94,
                    "status": "compliant",
                    "gaps": 2
                },
                "audit_logging": {
                    "score": 87,
                    "status": "partial",
                    "gaps": 3
                },
                "password_policies": {
                    "score": 91,
                    "status": "compliant",
                    "gaps": 1
                },
                "data_encryption": {
                    "score": 98,
                    "status": "compliant",
                    "gaps": 0
                }
            },
            "critical_gaps": [
                "Audit logging missing on database servers",
                "Segregation of duties violation in finance system",
                "Password rotation not enforced for service accounts"
            ],
            "remediation_cost": 45000,
            "compliance_deadline": (datetime.now() + timedelta(days=30)).isoformat()
        }
    
    def _generate_risk_data(self) -> Dict[str, Any]:
        """Generate data for risk assessment scenario"""
        return {
            "overall_risk_score": 72,
            "risk_categories": {
                "vulnerabilities": {
                    "score": 65,
                    "critical_count": 12,
                    "high_count": 34,
                    "trend": "increasing"
                },
                "access_management": {
                    "score": 78,
                    "issues": 8,
                    "trend": "stable"
                },
                "network_security": {
                    "score": 82,
                    "issues": 5,
                    "trend": "improving"
                },
                "data_protection": {
                    "score": 88,
                    "issues": 2,
                    "trend": "stable"
                }
            },
            "top_risks": [
                {
                    "risk": "Unpatched critical vulnerabilities",
                    "impact": "high",
                    "likelihood": "high",
                    "cost_to_fix": 25000,
                    "cost_if_exploited": 4500000
                },
                {
                    "risk": "Overprivileged user accounts",
                    "impact": "medium",
                    "likelihood": "medium",
                    "cost_to_fix": 15000,
                    "cost_if_exploited": 1200000
                }
            ],
            "industry_comparison": {
                "percentile": 68,
                "better_than": "68% of similar organizations",
                "areas_for_improvement": ["Vulnerability management", "Incident response"]
            }
        }
    
    def _generate_insider_threat_data(self) -> Dict[str, Any]:
        """Generate data for insider threat scenario"""
        return {
            "suspicious_users": [
                {
                    "user": "john.doe",
                    "risk_score": 85,
                    "anomalies": [
                        "After-hours access increased 300%",
                        "Accessed files outside normal job function",
                        "Large data downloads detected"
                    ],
                    "last_activity": (datetime.now() - timedelta(hours=2)).isoformat()
                },
                {
                    "user": "service_account_backup",
                    "risk_score": 72,
                    "anomalies": [
                        "Used from unusual locations",
                        "Accessed sensitive databases",
                        "Activity outside scheduled backup windows"
                    ],
                    "last_activity": (datetime.now() - timedelta(hours=6)).isoformat()
                }
            ],
            "behavioral_patterns": {
                "data_access_anomalies": 15,
                "time_based_anomalies": 8,
                "location_anomalies": 3,
                "privilege_escalations": 2
            },
            "data_at_risk": {
                "sensitive_files_accessed": 47,
                "customer_records_viewed": 1250,
                "financial_data_accessed": True,
                "intellectual_property_accessed": True
            }
        }
    
    def _generate_cloud_security_data(self) -> Dict[str, Any]:
        """Generate data for cloud security scenario"""
        return {
            "cloud_security_score": 78,
            "aws_regions_assessed": ["us-east-1", "us-west-2", "eu-west-1"],
            "security_findings": {
                "critical": 3,
                "high": 12,
                "medium": 28,
                "low": 45
            },
            "misconfigurations": [
                {
                    "type": "S3 Bucket Public Access",
                    "count": 3,
                    "risk": "critical",
                    "buckets": ["company-backups", "log-archive", "temp-storage"]
                },
                {
                    "type": "Overprivileged IAM Users",
                    "count": 12,
                    "risk": "high",
                    "users": ["admin-user-1", "developer-access", "service-account-prod"]
                },
                {
                    "type": "Security Group Overly Permissive",
                    "count": 8,
                    "risk": "medium",
                    "ports": ["22", "3389", "1433"]
                }
            ],
            "compliance_status": {
                "CIS_AWS_Foundations": 82,
                "AWS_Security_Best_Practices": 76,
                "PCI_DSS_Cloud": 88
            }
        }
    
    def _generate_incident_data(self) -> Dict[str, Any]:
        """Generate data for incident response scenario"""
        return {
            "incident_id": "INC-2024-001",
            "incident_type": "Malware Infection",
            "severity": "high",
            "status": "investigating",
            "timeline": [
                {
                    "timestamp": (datetime.now() - timedelta(days=2)).isoformat(),
                    "event": "Phishing email received by user alice.johnson",
                    "source": "email_logs"
                },
                {
                    "timestamp": (datetime.now() - timedelta(days=2, hours=-1)).isoformat(),
                    "event": "Malicious attachment opened",
                    "source": "endpoint_detection"
                },
                {
                    "timestamp": (datetime.now() - timedelta(days=1)).isoformat(),
                    "event": "Lateral movement to file server detected",
                    "source": "network_monitoring"
                },
                {
                    "timestamp": (datetime.now() - timedelta(hours=12)).isoformat(),
                    "event": "Suspicious file encryption activity",
                    "source": "file_integrity_monitoring"
                }
            ],
            "affected_systems": [
                "workstation-alice",
                "file-server-01",
                "backup-server-01"
            ],
            "indicators_of_compromise": [
                "MD5: a1b2c3d4e5f6789012345678901234567",
                "IP: 198.51.100.25",
                "Domain: malicious-site.example.com",
                "File: invoice_update.exe"
            ],
            "containment_actions": [
                "Isolate affected workstation",
                "Block malicious IP addresses",
                "Disable compromised user account",
                "Scan all systems for IOCs"
            ]
        }
    
    def _generate_generic_security_data(self) -> Dict[str, Any]:
        """Generate generic security data for unknown scenario types"""
        return {
            "security_events": 1000,
            "critical_alerts": 5,
            "high_alerts": 23,
            "medium_alerts": 67,
            "systems_monitored": 45,
            "users_active": 234,
            "threats_blocked": 156
        }
    
    def complete_scenario_step(self, scenario_context: Dict[str, Any], 
                            step_number: int, 
                            user_question: str) -> Dict[str, Any]:
        """Complete a step in the demonstration scenario"""
        scenario_id = scenario_context["scenario_id"]
        scenario = self.available_scenarios[scenario_id]
        
        if step_number >= len(scenario.key_questions):
            raise ValueError("Invalid step number")
        
        # Simulate AI response based on the scenario
        expected_question = scenario.key_questions[step_number]
        expected_insight = scenario.expected_insights[step_number]
        
        # Update progress
        scenario_context["current_step"] = step_number + 1
        scenario_context["progress_percentage"] = ((step_number + 1) / len(scenario.key_questions)) * 100
        
        response = {
            "step_number": step_number + 1,
            "user_question": user_question,
            "expected_question": expected_question,
            "ai_response": expected_insight,
            "scenario_data": scenario_context["sample_data"],
            "progress": scenario_context["progress_percentage"],
            "is_complete": scenario_context["current_step"] >= len(scenario.key_questions)
        }
        
        if response["is_complete"]:
            response["completion_summary"] = {
                "scenario_completed": scenario.title,
                "business_value_demonstrated": scenario.business_value,
                "key_capabilities_shown": [
                    "Natural language security questions",
                    "AI-powered threat analysis",
                    "Business-focused insights",
                    "Actionable recommendations",
                    "Real-time security assessment"
                ],
                "next_steps": [
                    "Try asking your own security questions",
                    "Upload your real security data",
                    "Explore other demonstration scenarios",
                    "Set up continuous monitoring"
                ]
            }
        
        return response
    
    def get_scenario_recommendations(self, session: OnboardingSession) -> List[Dict[str, Any]]:
        """Get personalized scenario recommendations"""
        recommendations = []
        
        # Recommend based on user's role or interests (if available)
        # For now, provide general recommendations
        
        recommendations.append({
            "scenario_id": "breach_detection",
            "title": "Detecting a Live Security Breach",
            "priority": "high",
            "reason": "Shows immediate threat detection capabilities",
            "business_impact": "Prevent millions in breach costs"
        })
        
        recommendations.append({
            "scenario_id": "compliance_audit",
            "title": "Instant SOX Compliance Assessment", 
            "priority": "high",
            "reason": "Demonstrates compliance automation value",
            "business_impact": "Reduce audit time from weeks to minutes"
        })
        
        recommendations.append({
            "scenario_id": "risk_assessment",
            "title": "Executive Risk Dashboard in 5 Minutes",
            "priority": "medium",
            "reason": "Perfect for executive decision making",
            "business_impact": "Data-driven security investment decisions"
        })
        
        return recommendations