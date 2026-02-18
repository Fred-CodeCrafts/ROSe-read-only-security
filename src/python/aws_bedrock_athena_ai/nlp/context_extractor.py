"""
Security Context Extraction System.

This module extracts contextual information from security questions,
including timeframes, systems, threat types, and other relevant context.
"""

import re
from typing import List, Dict, Optional, Set
from datetime import datetime, timedelta
import logging

from aws_bedrock_athena_ai.nlp.models import (
    QueryContext, SecurityEntity, EntityType, TimeRange,
    SecurityIntent, SecurityIntentType
)

logger = logging.getLogger(__name__)


class SecurityContextExtractor:
    """
    Extracts contextual information from security questions.
    
    Analyzes security questions to extract relevant context like timeframes,
    systems, users, threat types, and other information needed for analysis.
    """
    
    def __init__(self):
        self.system_keywords = self._initialize_system_keywords()
        self.threat_type_keywords = self._initialize_threat_type_keywords()
        self.priority_indicators = self._initialize_priority_indicators()
        self.role_indicators = self._initialize_role_indicators()
    
    def _initialize_system_keywords(self) -> Dict[str, List[str]]:
        """Initialize keywords for identifying different system types."""
        return {
            "web_servers": [
                "web server", "apache", "nginx", "iis", "tomcat", "website", 
                "web application", "http", "https"
            ],
            "databases": [
                "database", "mysql", "postgresql", "oracle", "sql server", 
                "mongodb", "redis", "db", "data store"
            ],
            "email_systems": [
                "email", "mail server", "exchange", "outlook", "smtp", 
                "imap", "pop3", "email system"
            ],
            "network_infrastructure": [
                "firewall", "router", "switch", "vpn", "dns", "dhcp", 
                "network", "infrastructure"
            ],
            "endpoints": [
                "workstation", "laptop", "desktop", "endpoint", "pc", 
                "computer", "device"
            ],
            "cloud_services": [
                "aws", "azure", "gcp", "cloud", "s3", "ec2", "lambda", 
                "kubernetes", "docker"
            ]
        }
    
    def _initialize_threat_type_keywords(self) -> Dict[str, List[str]]:
        """Initialize keywords for identifying threat types."""
        return {
            "malware": [
                "malware", "virus", "trojan", "worm", "spyware", "adware", 
                "rootkit", "backdoor"
            ],
            "ransomware": [
                "ransomware", "crypto", "encryption", "ransom", "locked files"
            ],
            "phishing": [
                "phishing", "spear phishing", "email attack", "social engineering",
                "fake email", "suspicious email"
            ],
            "ddos": [
                "ddos", "dos", "denial of service", "flood", "traffic spike"
            ],
            "injection": [
                "sql injection", "code injection", "xss", "cross-site scripting",
                "command injection"
            ],
            "brute_force": [
                "brute force", "password attack", "credential stuffing", 
                "dictionary attack"
            ],
            "insider_threat": [
                "insider threat", "rogue employee", "internal threat", 
                "privileged user"
            ],
            "apt": [
                "apt", "advanced persistent threat", "nation state", 
                "sophisticated attack"
            ]
        }
    
    def _initialize_priority_indicators(self) -> Dict[str, List[str]]:
        """Initialize indicators for determining query priority."""
        return {
            "critical": [
                "urgent", "critical", "emergency", "immediate", "asap", 
                "right now", "active attack", "ongoing", "live"
            ],
            "high": [
                "important", "high priority", "serious", "significant", 
                "major", "severe"
            ],
            "medium": [
                "moderate", "standard", "normal", "regular"
            ],
            "low": [
                "low priority", "minor", "routine", "when convenient"
            ]
        }
    
    def _initialize_role_indicators(self) -> Dict[str, List[str]]:
        """Initialize indicators for determining user role."""
        return {
            "executive": [
                "ceo", "cto", "ciso", "executive", "board", "management", 
                "business impact", "roi", "cost"
            ],
            "admin": [
                "admin", "administrator", "root", "system admin", "sysadmin",
                "infrastructure"
            ],
            "analyst": [
                "analyst", "security analyst", "soc", "technical", "investigate"
            ],
            "user": [
                "user", "employee", "staff", "end user", "business user"
            ]
        }
    
    def extract_context(
        self, 
        question: str, 
        intent: SecurityIntent,
        conversation_history: Optional[List[str]] = None
    ) -> QueryContext:
        """
        Extract contextual information from a security question.
        
        Args:
            question: The security question to analyze
            intent: The recognized security intent
            conversation_history: Previous questions in the conversation
            
        Returns:
            QueryContext with extracted contextual information
        """
        question_lower = question.lower().strip()
        
        # Extract timeframe
        timeframe = self._extract_timeframe(question, intent.entities)
        
        # Extract systems
        systems = self._extract_systems(question_lower)
        
        # Extract threat types
        threat_types = self._extract_threat_types(question_lower)
        
        # Extract IP addresses, users, and domains from entities
        ip_addresses = [
            entity.value for entity in intent.entities 
            if entity.entity_type == EntityType.IP_ADDRESS
        ]
        
        users = [
            entity.value for entity in intent.entities 
            if entity.entity_type == EntityType.USER
        ]
        
        domains = self._extract_domains(question)
        
        # Determine priority level
        priority_level = self._determine_priority(question_lower, intent.intent_type)
        
        # Determine user role
        user_role = self._determine_user_role(question_lower)
        
        # Suggest relevant data sources based on intent and context
        data_sources = self._suggest_data_sources(intent.intent_type, systems, threat_types)
        
        context = QueryContext(
            timeframe=timeframe,
            systems=systems,
            data_sources=data_sources,
            priority_level=priority_level,
            user_role=user_role,
            conversation_history=conversation_history or [],
            threat_types=threat_types,
            ip_addresses=ip_addresses,
            users=users,
            domains=domains
        )
        
        # Add current question to history
        context.add_to_history(question)
        
        return context
    
    def _extract_timeframe(self, question: str, entities: List[SecurityEntity]) -> Optional[TimeRange]:
        """Extract timeframe information from the question."""
        # First check if we have timeframe entities
        timeframe_entities = [
            entity for entity in entities 
            if entity.entity_type == EntityType.TIMEFRAME
        ]
        
        if timeframe_entities:
            # Use the first timeframe entity found
            timeframe_text = timeframe_entities[0].value
            return TimeRange.from_relative_description(timeframe_text)
        
        # Fallback to pattern matching
        question_lower = question.lower()
        
        # Common timeframe patterns
        timeframe_patterns = {
            r"(last|past)\s+(\d+)\s+(hour|day|week|month|year)s?": lambda m: self._create_relative_timerange(int(m.group(2)), m.group(3)),
            r"(today|this\s+day)": lambda m: TimeRange.from_relative_description("today"),
            r"(yesterday)": lambda m: TimeRange.from_relative_description("yesterday"),
            r"(last|past)\s+(week|month|year)": lambda m: TimeRange.from_relative_description(f"last {m.group(2)}"),
            r"(this\s+week|this\s+month|this\s+year)": lambda m: TimeRange.from_relative_description(m.group(1)),
            r"(24\s+hours?|one\s+day)": lambda m: TimeRange.from_relative_description("past 24 hours"),
            r"(right\s+now|currently|at\s+this\s+moment)": lambda m: TimeRange.from_relative_description("right now")
        }
        
        for pattern, timerange_func in timeframe_patterns.items():
            match = re.search(pattern, question_lower)
            if match:
                return timerange_func(match)
        
        return None
    
    def _create_relative_timerange(self, amount: int, unit: str) -> TimeRange:
        """Create a TimeRange from relative amount and unit."""
        now = datetime.now()
        
        if unit.startswith("hour"):
            start_time = now - timedelta(hours=amount)
        elif unit.startswith("day"):
            start_time = now - timedelta(days=amount)
        elif unit.startswith("week"):
            start_time = now - timedelta(weeks=amount)
        elif unit.startswith("month"):
            start_time = now - timedelta(days=amount * 30)  # Approximate
        elif unit.startswith("year"):
            start_time = now - timedelta(days=amount * 365)  # Approximate
        else:
            start_time = now - timedelta(days=1)  # Default to 1 day
        
        return TimeRange(
            start=start_time,
            end=now,
            relative_description=f"past {amount} {unit}{'s' if amount > 1 else ''}"
        )
    
    def _extract_systems(self, question: str) -> List[str]:
        """Extract system types and names from the question."""
        systems = []
        
        for system_type, keywords in self.system_keywords.items():
            for keyword in keywords:
                if keyword in question:
                    systems.append(system_type)
                    break  # Avoid duplicates for the same system type
        
        # Also look for specific system names (hostnames, IPs, etc.)
        # Pattern for hostnames
        hostname_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\b'
        hostnames = re.findall(hostname_pattern, question)
        
        # Filter out common words that might match the hostname pattern
        common_words = {"the", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by"}
        for hostname_match in hostnames:
            hostname = hostname_match[0] if isinstance(hostname_match, tuple) else hostname_match
            if hostname.lower() not in common_words and len(hostname) > 2:
                systems.append(hostname)
        
        return list(set(systems))  # Remove duplicates
    
    def _extract_threat_types(self, question: str) -> List[str]:
        """Extract threat types mentioned in the question."""
        threat_types = []
        
        for threat_type, keywords in self.threat_type_keywords.items():
            for keyword in keywords:
                if keyword in question:
                    threat_types.append(threat_type)
                    break  # Avoid duplicates for the same threat type
        
        return threat_types
    
    def _extract_domains(self, question: str) -> List[str]:
        """Extract domain names from the question."""
        # Pattern for domain names
        domain_pattern = r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, question)
        
        # Clean up the results (regex returns tuples for groups)
        clean_domains = []
        for domain in domains:
            if isinstance(domain, tuple):
                # Reconstruct the full domain from the tuple
                full_domain = domain[0] + '.' + question[question.find(domain[0]):].split()[0].split('.', 1)[1]
                clean_domains.append(full_domain)
            else:
                clean_domains.append(domain)
        
        return clean_domains
    
    def _determine_priority(self, question: str, intent_type: SecurityIntentType) -> str:
        """Determine the priority level of the security question."""
        # Check for explicit priority indicators
        for priority, indicators in self.priority_indicators.items():
            if any(indicator in question for indicator in indicators):
                return priority
        
        # Infer priority from intent type and context
        if intent_type in [SecurityIntentType.DATA_BREACH, SecurityIntentType.INCIDENT_INVESTIGATION]:
            return "critical"
        elif intent_type in [SecurityIntentType.THREAT_HUNTING, SecurityIntentType.ANOMALY_DETECTION]:
            return "high"
        elif intent_type in [SecurityIntentType.VULNERABILITY_SCAN, SecurityIntentType.ACCESS_REVIEW]:
            return "medium"
        else:
            return "medium"  # Default priority
    
    def _determine_user_role(self, question: str) -> str:
        """Determine the likely role of the user asking the question."""
        for role, indicators in self.role_indicators.items():
            if any(indicator in question for indicator in indicators):
                return role
        
        return "analyst"  # Default role
    
    def _suggest_data_sources(
        self, 
        intent_type: SecurityIntentType, 
        systems: List[str], 
        threat_types: List[str]
    ) -> List[str]:
        """Suggest relevant data sources based on intent and context."""
        data_sources = []
        
        # Base data sources for different intent types
        intent_data_sources = {
            SecurityIntentType.THREAT_HUNTING: [
                "security_events", "network_logs", "endpoint_logs", "dns_logs"
            ],
            SecurityIntentType.COMPLIANCE_CHECK: [
                "system_configs", "audit_logs", "policy_violations", "access_logs"
            ],
            SecurityIntentType.RISK_ASSESSMENT: [
                "vulnerability_scans", "system_configs", "asset_inventory", "threat_intelligence"
            ],
            SecurityIntentType.INCIDENT_INVESTIGATION: [
                "security_events", "network_logs", "endpoint_logs", "email_logs", "user_activity"
            ],
            SecurityIntentType.VULNERABILITY_SCAN: [
                "vulnerability_scans", "patch_status", "system_configs", "asset_inventory"
            ],
            SecurityIntentType.ACCESS_REVIEW: [
                "access_logs", "user_activity", "authentication_logs", "privilege_changes"
            ],
            SecurityIntentType.ANOMALY_DETECTION: [
                "network_logs", "user_activity", "system_performance", "security_events"
            ],
            SecurityIntentType.DATA_BREACH: [
                "security_events", "data_access_logs", "network_logs", "email_logs", "file_activity"
            ]
        }
        
        # Add base data sources for the intent type
        if intent_type in intent_data_sources:
            data_sources.extend(intent_data_sources[intent_type])
        
        # Add system-specific data sources
        system_data_sources = {
            "web_servers": ["web_logs", "application_logs", "http_access_logs"],
            "databases": ["database_logs", "query_logs", "db_audit_logs"],
            "email_systems": ["email_logs", "smtp_logs", "mailbox_audit"],
            "network_infrastructure": ["network_logs", "firewall_logs", "router_logs"],
            "endpoints": ["endpoint_logs", "process_logs", "file_activity"],
            "cloud_services": ["cloud_audit_logs", "api_logs", "resource_logs"]
        }
        
        for system in systems:
            if system in system_data_sources:
                data_sources.extend(system_data_sources[system])
        
        # Add threat-specific data sources
        threat_data_sources = {
            "malware": ["antivirus_logs", "endpoint_detection", "file_analysis"],
            "phishing": ["email_logs", "url_analysis", "user_reports"],
            "ddos": ["network_logs", "traffic_analysis", "bandwidth_monitoring"],
            "brute_force": ["authentication_logs", "failed_logins", "account_lockouts"]
        }
        
        for threat_type in threat_types:
            if threat_type in threat_data_sources:
                data_sources.extend(threat_data_sources[threat_type])
        
        return list(set(data_sources))  # Remove duplicates