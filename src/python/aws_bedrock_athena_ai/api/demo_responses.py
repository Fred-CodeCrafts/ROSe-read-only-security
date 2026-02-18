"""
Demo Response Generator Module

Generates realistic mock responses for security queries when AWS is unavailable.
Provides keyword-based responses and demo statistics.
"""

import uuid
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class DemoResponseGenerator:
    """
    Generates realistic demo responses for security queries.
    
    Uses keyword matching to provide contextually relevant responses
    without requiring AWS Bedrock or Athena.
    """
    
    def __init__(self):
        """Initialize the demo response generator with pre-built templates"""
        self._response_templates = self._build_response_templates()
        self._query_count = 0
        self._total_response_time = 0
        self._threats_detected = 3  # Demo value
    
    def _build_response_templates(self) -> Dict[str, Dict[str, Any]]:
        """
        Build pre-configured response templates for common security questions.
        
        Returns:
            Dictionary mapping keywords to response templates
        """
        return {
            "risk": {
                "keywords": ["risk", "risks", "threat", "threats", "vulnerability", "vulnerabilities"],
                "executive_summary": (
                    "Based on analysis of your security posture, we've identified 3 high-priority risks:\n\n"
                    "1. **Unauthorized Access Attempts**: 47 failed login attempts detected from suspicious IPs\n"
                    "2. **Unpatched Systems**: 12 systems running outdated software with known vulnerabilities\n"
                    "3. **Data Exposure**: 2 S3 buckets with overly permissive access policies\n\n"
                    "These risks require immediate attention to prevent potential security incidents."
                ),
                "technical_details": {
                    "failed_logins": {
                        "count": 47,
                        "unique_ips": 8,
                        "top_targeted_accounts": ["admin", "root", "service-account"],
                        "geographic_distribution": ["Unknown (45%)", "Russia (30%)", "China (25%)"]
                    },
                    "unpatched_systems": {
                        "count": 12,
                        "critical_cves": ["CVE-2024-1234", "CVE-2024-5678"],
                        "affected_services": ["web-server-01", "db-server-03", "api-gateway-02"]
                    },
                    "exposed_buckets": {
                        "count": 2,
                        "bucket_names": ["logs-backup", "temp-data"],
                        "exposure_level": "Public Read Access"
                    }
                },
                "recommendations": [
                    {
                        "priority": "Critical",
                        "title": "Implement IP-based Access Controls",
                        "description": "Block suspicious IPs and implement geo-fencing for administrative access",
                        "effort": "Low",
                        "impact": "High"
                    },
                    {
                        "priority": "High",
                        "title": "Patch Vulnerable Systems",
                        "description": "Apply security patches to all 12 identified systems within 48 hours",
                        "effort": "Medium",
                        "impact": "High"
                    },
                    {
                        "priority": "High",
                        "title": "Restrict S3 Bucket Permissions",
                        "description": "Review and tighten access policies on exposed S3 buckets",
                        "effort": "Low",
                        "impact": "High"
                    }
                ],
                "confidence_score": 0.92
            },
            "login": {
                "keywords": ["login", "authentication", "access", "unauthorized", "failed"],
                "executive_summary": (
                    "Authentication analysis reveals concerning patterns:\n\n"
                    "- **47 failed login attempts** in the last 24 hours\n"
                    "- **8 unique suspicious IP addresses** attempting access\n"
                    "- **3 accounts** targeted most frequently: admin, root, service-account\n\n"
                    "This suggests a coordinated brute-force attack. Immediate action recommended."
                ),
                "technical_details": {
                    "failed_attempts": 47,
                    "time_window": "24 hours",
                    "attack_pattern": "Distributed brute-force",
                    "targeted_accounts": ["admin", "root", "service-account"],
                    "source_ips": [
                        "203.0.113.45 (Russia)",
                        "198.51.100.23 (China)",
                        "192.0.2.67 (Unknown)"
                    ],
                    "attack_velocity": "2-3 attempts per minute"
                },
                "recommendations": [
                    {
                        "priority": "Critical",
                        "title": "Enable Multi-Factor Authentication",
                        "description": "Require MFA for all administrative accounts immediately",
                        "effort": "Low",
                        "impact": "High"
                    },
                    {
                        "priority": "Critical",
                        "title": "Block Suspicious IPs",
                        "description": "Add identified IPs to firewall blocklist",
                        "effort": "Low",
                        "impact": "High"
                    },
                    {
                        "priority": "High",
                        "title": "Implement Account Lockout Policy",
                        "description": "Lock accounts after 5 failed attempts for 30 minutes",
                        "effort": "Medium",
                        "impact": "Medium"
                    }
                ],
                "confidence_score": 0.95
            },
            "s3": {
                "keywords": ["s3", "bucket", "storage", "data", "exposure", "public"],
                "executive_summary": (
                    "S3 security audit identified potential data exposure risks:\n\n"
                    "- **2 buckets** with public read access\n"
                    "- **1 bucket** with overly permissive IAM policies\n"
                    "- **Estimated 450GB** of data potentially exposed\n\n"
                    "Immediate remediation required to prevent data breaches."
                ),
                "technical_details": {
                    "total_buckets_scanned": 15,
                    "vulnerable_buckets": 2,
                    "exposure_details": [
                        {
                            "bucket": "logs-backup",
                            "issue": "Public Read Access",
                            "data_size": "320GB",
                            "contains": "Application logs, system logs"
                        },
                        {
                            "bucket": "temp-data",
                            "issue": "Public Read Access",
                            "data_size": "130GB",
                            "contains": "Temporary files, cache data"
                        }
                    ],
                    "compliance_impact": "GDPR, HIPAA violations possible"
                },
                "recommendations": [
                    {
                        "priority": "Critical",
                        "title": "Remove Public Access",
                        "description": "Immediately disable public access on identified buckets",
                        "effort": "Low",
                        "impact": "High"
                    },
                    {
                        "priority": "High",
                        "title": "Enable S3 Block Public Access",
                        "description": "Enable account-level S3 Block Public Access settings",
                        "effort": "Low",
                        "impact": "High"
                    },
                    {
                        "priority": "Medium",
                        "title": "Implement Bucket Policies",
                        "description": "Review and implement least-privilege bucket policies",
                        "effort": "Medium",
                        "impact": "Medium"
                    }
                ],
                "confidence_score": 0.88
            },
            "patch": {
                "keywords": ["patch", "update", "vulnerability", "cve", "outdated"],
                "executive_summary": (
                    "System patch analysis reveals critical vulnerabilities:\n\n"
                    "- **12 systems** running outdated software\n"
                    "- **2 critical CVEs** affecting production systems\n"
                    "- **Average patch lag**: 45 days behind current versions\n\n"
                    "Urgent patching required to close security gaps."
                ),
                "technical_details": {
                    "unpatched_systems": 12,
                    "critical_cves": [
                        {
                            "id": "CVE-2024-1234",
                            "severity": "Critical (9.8)",
                            "affected_systems": ["web-server-01", "web-server-02"],
                            "description": "Remote code execution vulnerability"
                        },
                        {
                            "id": "CVE-2024-5678",
                            "severity": "High (8.1)",
                            "affected_systems": ["db-server-03", "api-gateway-02"],
                            "description": "Privilege escalation vulnerability"
                        }
                    ],
                    "patch_lag_days": 45,
                    "compliance_status": "Non-compliant with security baseline"
                },
                "recommendations": [
                    {
                        "priority": "Critical",
                        "title": "Emergency Patching",
                        "description": "Apply critical patches to all affected systems within 48 hours",
                        "effort": "Medium",
                        "impact": "High"
                    },
                    {
                        "priority": "High",
                        "title": "Implement Automated Patching",
                        "description": "Set up automated patch management system",
                        "effort": "High",
                        "impact": "High"
                    },
                    {
                        "priority": "Medium",
                        "title": "Establish Patch Schedule",
                        "description": "Create and enforce regular patching schedule",
                        "effort": "Low",
                        "impact": "Medium"
                    }
                ],
                "confidence_score": 0.91
            },
            "default": {
                "keywords": [],
                "executive_summary": (
                    "Security analysis completed successfully. Here's what we found:\n\n"
                    "**Overall Security Posture**: Moderate\n\n"
                    "Key findings:\n"
                    "- 47 failed login attempts detected (potential brute-force attack)\n"
                    "- 12 systems require security patches\n"
                    "- 2 S3 buckets with overly permissive access\n"
                    "- 3 high-priority security recommendations\n\n"
                    "Your security team should prioritize addressing the failed login attempts "
                    "and patching vulnerable systems."
                ),
                "technical_details": {
                    "analysis_scope": "Last 24 hours",
                    "data_sources": ["CloudTrail", "VPC Flow Logs", "S3 Access Logs"],
                    "events_analyzed": 1247,
                    "anomalies_detected": 3,
                    "security_score": 72
                },
                "recommendations": [
                    {
                        "priority": "High",
                        "title": "Review Failed Login Attempts",
                        "description": "Investigate and block suspicious IP addresses",
                        "effort": "Low",
                        "impact": "High"
                    },
                    {
                        "priority": "High",
                        "title": "Patch Vulnerable Systems",
                        "description": "Apply security updates to identified systems",
                        "effort": "Medium",
                        "impact": "High"
                    },
                    {
                        "priority": "Medium",
                        "title": "Audit S3 Permissions",
                        "description": "Review and tighten S3 bucket access policies",
                        "effort": "Medium",
                        "impact": "Medium"
                    }
                ],
                "confidence_score": 0.85
            }
        }
    
    def _match_template(self, question: str) -> Dict[str, Any]:
        """
        Match question to appropriate response template based on keywords.
        
        Args:
            question: The security question
            
        Returns:
            Matching response template
        """
        question_lower = question.lower()
        
        # Check each template for keyword matches
        for template_name, template in self._response_templates.items():
            if template_name == "default":
                continue
            
            for keyword in template["keywords"]:
                if keyword in question_lower:
                    logger.debug(f"Matched template '{template_name}' for question")
                    return template
        
        # Return default template if no match
        logger.debug("Using default template for question")
        return self._response_templates["default"]
    
    def generate_security_response(
        self,
        question: str,
        conversation_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Generate a demo response based on question keywords.
        
        Args:
            question: The security question
            conversation_id: Optional conversation ID
            
        Returns:
            SecurityQuestionResponse-compatible dictionary
        """
        # Generate conversation ID if not provided
        if not conversation_id:
            conversation_id = str(uuid.uuid4())
        
        # Match question to template
        template = self._match_template(question)
        
        # Simulate processing time
        processing_time = 245.0  # Demo value in milliseconds
        
        # Update stats
        self._query_count += 1
        self._total_response_time += processing_time
        
        # Build response
        response = {
            "success": True,
            "conversation_id": conversation_id,
            "needs_clarification": False,
            "clarification_questions": None,
            "executive_summary": template["executive_summary"],
            "technical_details": template["technical_details"],
            "recommendations": template["recommendations"],
            "visualizations": [
                {
                    "type": "bar_chart",
                    "title": "Security Events by Type",
                    "data": {
                        "Failed Logins": 47,
                        "Unpatched Systems": 12,
                        "Exposed Buckets": 2
                    }
                },
                {
                    "type": "pie_chart",
                    "title": "Risk Distribution",
                    "data": {
                        "Critical": 2,
                        "High": 3,
                        "Medium": 5,
                        "Low": 8
                    }
                }
            ],
            "action_plan": {
                "immediate_actions": [
                    "Block suspicious IPs attempting brute-force attacks",
                    "Remove public access from exposed S3 buckets"
                ],
                "short_term_actions": [
                    "Apply security patches to vulnerable systems",
                    "Enable MFA for administrative accounts"
                ],
                "long_term_actions": [
                    "Implement automated patch management",
                    "Establish regular security audit schedule"
                ]
            },
            "processing_time_ms": processing_time,
            "confidence_score": template["confidence_score"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        logger.info(f"Generated demo response for question: {question[:50]}...")
        return response
    
    def get_demo_stats(self) -> Dict[str, Any]:
        """
        Return demo statistics for quick stats display.
        
        Returns:
            Dictionary with demo statistics
        """
        avg_response_time = (
            self._total_response_time / self._query_count 
            if self._query_count > 0 
            else 245.0
        )
        
        return {
            "queries_today": max(12, self._query_count),  # Show at least 12
            "avg_response_time": round(avg_response_time, 1),
            "threats_detected": self._threats_detected,
            "mode": "demo"
        }
