"""
Threat Analyzer - Core threat pattern recognition using AWS Bedrock.

This module analyzes security data to identify threats, suspicious patterns,
and security incidents using advanced AI reasoning capabilities.
"""

import json
import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError

from aws_bedrock_athena_ai.reasoning_engine.models import (
    Threat, ThreatType, ThreatSeverity, Evidence, Pattern, Event
)
from aws_bedrock_athena_ai.data_detective.models import QueryResults


logger = logging.getLogger(__name__)


class ThreatAnalyzer:
    """
    Analyzes security data to identify threats and suspicious patterns
    using AWS Bedrock foundation models.
    """
    
    def __init__(self, region_name: str = "us-east-1"):
        """Initialize the threat analyzer with AWS Bedrock client."""
        self.bedrock_client = boto3.client('bedrock-runtime', region_name=region_name)
        self.model_id = "anthropic.claude-3-haiku-20240307-v1:0"  # Cost-effective model
        self.region_name = region_name
        
        # Enhanced threat detection patterns
        self.threat_patterns = {
            'brute_force': ['failed login', 'authentication failure', 'multiple attempts'],
            'malware': ['suspicious file', 'virus detected', 'malicious payload'],
            'data_exfiltration': ['large data transfer', 'unusual upload', 'sensitive data access'],
            'privilege_escalation': ['admin access', 'elevated privileges', 'sudo usage'],
            'lateral_movement': ['network scanning', 'port scanning', 'internal reconnaissance']
        }
        
    def validate_bedrock_connection(self) -> bool:
        """
        Validate connection to AWS Bedrock service.
        
        Returns:
            True if connection is successful, False otherwise
        """
        try:
            # Test connection by listing available models
            response = self.bedrock_client.list_foundation_models()
            available_models = [model['modelId'] for model in response.get('modelSummaries', [])]
            
            if self.model_id in available_models:
                logger.info(f"✅ Bedrock connection validated, model {self.model_id} available")
                return True
            else:
                logger.warning(f"⚠️ Model {self.model_id} not available. Available models: {available_models[:5]}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Bedrock connection failed: {str(e)}")
            return False
    
    def analyze_security_patterns(self, data: QueryResults) -> List[Threat]:
        """
        Analyze security data to identify threat patterns.
        
        Args:
            data: Query results from Smart Data Detective
            
        Returns:
            List of identified threats
        """
        try:
            logger.info(f"Analyzing security patterns in {len(data.data)} data points")
            
            # Prepare data for AI analysis
            analysis_prompt = self._build_threat_analysis_prompt(data)
            
            # Get AI analysis from Bedrock
            ai_response = self._call_bedrock_model(analysis_prompt)
            
            # Parse AI response into threat objects
            threats = self._parse_threat_analysis(ai_response, data)
            
            logger.info(f"Identified {len(threats)} potential threats")
            return threats
            
        except Exception as e:
            logger.error(f"Error analyzing security patterns: {str(e)}")
            return []
    
    def identify_suspicious_patterns(self, data: QueryResults) -> List[Pattern]:
        """
        Identify suspicious patterns in security data.
        
        Args:
            data: Query results to analyze
            
        Returns:
            List of suspicious patterns found
        """
        try:
            pattern_prompt = self._build_pattern_analysis_prompt(data)
            ai_response = self._call_bedrock_model(pattern_prompt)
            patterns = self._parse_pattern_analysis(ai_response)
            
            logger.info(f"Identified {len(patterns)} suspicious patterns")
            return patterns
            
        except Exception as e:
            logger.error(f"Error identifying patterns: {str(e)}")
            return []
    
    def _build_threat_analysis_prompt(self, data: QueryResults) -> str:
        """Build prompt for threat analysis."""
        # Sample data for analysis (limit to avoid token limits)
        sample_data = data.data[:50] if len(data.data) > 50 else data.data
        
        prompt = f"""
You are a senior cybersecurity analyst with 15+ years of experience in threat hunting and incident response. 
Analyze the following security data and identify potential threats, attacks, or suspicious activities.

Data Source: {data.source_tables[0] if data.source_tables else 'unknown'}
Query: {data.query_sql}
Total Records: {len(data.data)}
Sample Data (first 50 records):
{json.dumps(sample_data, indent=2, default=str)}

THREAT ANALYSIS FRAMEWORK:
Apply the MITRE ATT&CK framework and consider these threat categories:
1. Initial Access (phishing, exploit public-facing apps, valid accounts)
2. Execution (malicious files, scripts, command execution)
3. Persistence (backdoors, scheduled tasks, registry modifications)
4. Privilege Escalation (exploitation, token manipulation)
5. Defense Evasion (obfuscation, disabling security tools)
6. Credential Access (credential dumping, brute force)
7. Discovery (network/system discovery, account discovery)
8. Lateral Movement (remote services, internal spearphishing)
9. Collection (data from information repositories, screen capture)
10. Exfiltration (data transfer, exfiltration over C2 channel)
11. Impact (data destruction, service stop, defacement)

ANALYSIS REQUIREMENTS:
For each threat identified, provide:
- Threat type and severity level (critical/high/medium/low/info)
- Clear description with technical details
- Evidence supporting the finding with confidence scores
- Affected systems/users/assets
- Timeline of events if discernible
- Indicators of Compromise (IOCs)
- Potential attack progression
- Business impact assessment

DETECTION PATTERNS TO CONSIDER:
- Unusual authentication patterns (failed logins, off-hours access)
- Network anomalies (unusual traffic, new connections, port scanning)
- File system changes (new executables, modified system files)
- Process anomalies (suspicious processes, command line arguments)
- Data access patterns (bulk downloads, sensitive file access)
- Configuration changes (security settings, user permissions)

Format your response as a JSON array of threat objects with this structure:
{{
  "threats": [
    {{
      "threat_type": "intrusion|malware|data_breach|insider_threat|phishing|ddos|vulnerability|compliance_violation|suspicious_activity|configuration_issue",
      "severity": "critical|high|medium|low|info",
      "title": "Brief threat title",
      "description": "Detailed description of the threat with technical analysis",
      "affected_systems": ["system1", "system2"],
      "indicators": ["IOC1", "IOC2", "IOC3"],
      "evidence": [
        {{
          "source": "log_source",
          "description": "specific evidence description",
          "confidence": 0.9
        }}
      ],
      "confidence": 0.85,
      "first_seen": "2024-01-01T10:00:00Z",
      "last_seen": "2024-01-01T12:00:00Z",
      "mitre_tactics": ["initial-access", "persistence"],
      "business_impact": "potential impact on business operations"
    }}
  ]
}}

IMPORTANT: 
- Focus on actionable threats with clear evidence
- Avoid false positives - only flag genuine security concerns
- Provide confidence scores based on evidence strength
- Consider context and normal business operations
- Prioritize threats by potential business impact
"""
        return prompt
    
    def _build_pattern_analysis_prompt(self, data: QueryResults) -> str:
        """Build prompt for pattern analysis."""
        sample_data = data.data[:30] if len(data.data) > 30 else data.data
        
        prompt = f"""
As a cybersecurity expert, analyze the following security data for suspicious patterns, anomalies, or trends that could indicate security issues.

Data: {json.dumps(sample_data, indent=2, default=str)}

Identify patterns such as:
- Unusual access patterns
- Repeated failed attempts
- Anomalous network traffic
- Configuration drift
- Privilege escalation attempts
- Data exfiltration indicators

Format response as JSON:
{{
  "patterns": [
    {{
      "pattern_type": "access_anomaly|failed_attempts|network_anomaly|config_drift|privilege_escalation|data_exfiltration",
      "description": "Pattern description",
      "indicators": ["indicator1", "indicator2"],
      "frequency": 5,
      "confidence": 0.8
    }}
  ]
}}
"""
        return prompt
    
    def _call_bedrock_model(self, prompt: str) -> str:
        """Call AWS Bedrock model with the given prompt."""
        try:
            # Prepare request for Claude model
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4000,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.1,  # Low temperature for consistent analysis
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
    
    def _parse_threat_analysis(self, ai_response: str, original_data: QueryResults) -> List[Threat]:
        """Parse AI response into Threat objects."""
        try:
            # Extract JSON from response
            response_data = self._extract_json_from_response(ai_response)
            threats = []
            
            if 'threats' in response_data:
                for threat_data in response_data['threats']:
                    threat = self._create_threat_from_data(threat_data, original_data)
                    if threat:
                        threats.append(threat)
            
            return threats
            
        except Exception as e:
            logger.error(f"Error parsing threat analysis: {str(e)}")
            return []
    
    def _parse_pattern_analysis(self, ai_response: str) -> List[Pattern]:
        """Parse AI response into Pattern objects."""
        try:
            response_data = self._extract_json_from_response(ai_response)
            patterns = []
            
            if 'patterns' in response_data:
                for pattern_data in response_data['patterns']:
                    pattern = Pattern(
                        pattern_type=pattern_data.get('pattern_type', 'unknown'),
                        description=pattern_data.get('description', ''),
                        indicators=pattern_data.get('indicators', []),
                        frequency=pattern_data.get('frequency', 1),
                        confidence=pattern_data.get('confidence', 0.5)
                    )
                    patterns.append(pattern)
            
            return patterns
            
        except Exception as e:
            logger.error(f"Error parsing pattern analysis: {str(e)}")
            return []
    
    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """Extract JSON from AI response, handling various formats."""
        try:
            # Try to parse as direct JSON
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
            
            # Return empty structure if no valid JSON found
            logger.warning("Could not extract valid JSON from AI response")
            return {"threats": [], "patterns": []}
    
    def _create_threat_from_data(self, threat_data: Dict[str, Any], original_data: QueryResults) -> Optional[Threat]:
        """Create a Threat object from parsed data."""
        try:
            # Map string values to enums
            threat_type = ThreatType(threat_data.get('threat_type', 'suspicious_activity'))
            severity = ThreatSeverity(threat_data.get('severity', 'medium'))
            
            # Create evidence objects
            evidence = []
            for ev_data in threat_data.get('evidence', []):
                evidence.append(Evidence(
                    source=ev_data.get('source', original_data.source_tables[0] if original_data.source_tables else 'unknown'),
                    timestamp=datetime.now(),
                    description=ev_data.get('description', ''),
                    raw_data=ev_data,
                    confidence=ev_data.get('confidence', 0.5)
                ))
            
            # Parse timestamps
            first_seen = None
            last_seen = None
            if threat_data.get('first_seen'):
                try:
                    first_seen = datetime.fromisoformat(threat_data['first_seen'].replace('Z', '+00:00'))
                except:
                    pass
            if threat_data.get('last_seen'):
                try:
                    last_seen = datetime.fromisoformat(threat_data['last_seen'].replace('Z', '+00:00'))
                except:
                    pass
            
            # Create timeline events from evidence
            timeline = []
            for ev in evidence:
                timeline.append(Event(
                    timestamp=ev.timestamp,
                    event_type=threat_type.value,
                    description=ev.description,
                    source=ev.source,
                    severity=severity
                ))
            
            return Threat(
                threat_id=str(uuid.uuid4()),
                threat_type=threat_type,
                severity=severity,
                title=threat_data.get('title', 'Unknown Threat'),
                description=threat_data.get('description', ''),
                affected_systems=threat_data.get('affected_systems', []),
                indicators=threat_data.get('indicators', []),
                timeline=timeline,
                evidence=evidence,
                confidence=threat_data.get('confidence', 0.5),
                first_seen=first_seen,
                last_seen=last_seen
            )
            
        except Exception as e:
            logger.error(f"Error creating threat object: {str(e)}")
            return None