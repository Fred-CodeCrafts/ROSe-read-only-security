"""
Automated Security Alert Analysis Dashboard

This module implements a hackathon-inspired cybersecurity dashboard that provides
real-time security insights, threat pattern analysis, and interactive demonstrations
of the platform's analytical capabilities.
"""

import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import logging
from pathlib import Path

# Import existing platform components
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from src.python.ai_analyst.oss_security_analyst import OSSSecurityAnalyst
from src.python.data_intelligence.oss_data_intelligence import OSSDataIntelligence
from src.python.data_protection.access_analyzer import AccessPatternAnalyzer
from src.python.agentic_modules.dependency_analyzer import OSSDependencyAnalyzer

@dataclass
class SecurityAlert:
    """Represents a security alert with comprehensive metadata."""
    alert_id: str
    timestamp: datetime
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    alert_type: str  # INTRUSION, MALWARE, POLICY_VIOLATION, ANOMALY
    source_ip: str
    target_ip: str
    description: str
    threat_indicators: List[str]
    affected_assets: List[str]
    confidence_score: float
    status: str  # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE

@dataclass
class ThreatPattern:
    """Represents an identified threat pattern."""
    pattern_id: str
    pattern_name: str
    frequency: int
    severity_distribution: Dict[str, int]
    first_seen: datetime
    last_seen: datetime
    indicators: List[str]
    mitigation_recommendations: List[str]

@dataclass
class SecurityMetrics:
    """Security metrics for dashboard visualization."""
    total_alerts: int
    critical_alerts: int
    resolved_alerts: int
    false_positives: int
    mean_resolution_time: float
    threat_patterns_detected: int
    security_score: float
    trend_direction: str  # IMPROVING, STABLE, DEGRADING

class SecurityAlertAnalyzer:
    """
    Automated security alert analysis engine that processes security events,
    identifies patterns, and generates actionable insights.
    """
    
    def __init__(self, data_path: str = "data/synthetic"):
        self.data_path = Path(data_path)
        self.logger = logging.getLogger(__name__)
        
        # Initialize platform components
        self.ai_analyst = OSSSecurityAnalyst()
        self.data_intelligence = OSSDataIntelligence()
        self.access_analyzer = AccessPatternAnalyzer()
        self.dependency_analyzer = OSSDependencyAnalyzer()
        
        # Load synthetic data
        self.security_events = self._load_security_events()
        self.network_traffic = self._load_network_traffic()
        self.access_logs = self._load_access_logs()
        
    def _load_security_events(self) -> List[Dict]:
        """Load synthetic security events data."""
        try:
            events_file = self.data_path / "security_events.json"
            if events_file.exists():
                with open(events_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            self.logger.error(f"Failed to load security events: {e}")
            return []
    
    def _load_network_traffic(self) -> List[Dict]:
        """Load synthetic network traffic data."""
        try:
            traffic_file = self.data_path / "network_traffic.json"
            if traffic_file.exists():
                with open(traffic_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            self.logger.error(f"Failed to load network traffic: {e}")
            return []
    
    def _load_access_logs(self) -> List[Dict]:
        """Load synthetic access logs data."""
        try:
            access_file = self.data_path / "access_logs.json"
            if access_file.exists():
                with open(access_file, 'r') as f:
                    return json.load(f)
            return []
        except Exception as e:
            self.logger.error(f"Failed to load access logs: {e}")
            return []
    
    def analyze_security_alerts(self) -> List[SecurityAlert]:
        """
        Analyze security events and generate structured security alerts.
        
        Returns:
            List of SecurityAlert objects with comprehensive analysis
        """
        alerts = []
        
        for event in self.security_events:
            try:
                # Convert event to SecurityAlert
                alert = SecurityAlert(
                    alert_id=event.get('event_id', f"alert_{len(alerts)}"),
                    timestamp=datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat())),
                    severity=event.get('severity', 'MEDIUM'),
                    alert_type=event.get('event_type', 'ANOMALY'),
                    source_ip=event.get('source_ip', '0.0.0.0'),
                    target_ip=event.get('target_ip', '0.0.0.0'),
                    description=event.get('description', 'Security event detected'),
                    threat_indicators=event.get('indicators', []),
                    affected_assets=event.get('affected_assets', []),
                    confidence_score=event.get('confidence', 0.5),
                    status='OPEN'
                )
                alerts.append(alert)
            except Exception as e:
                self.logger.error(f"Failed to process security event: {e}")
                continue
        
        return alerts
    
    def identify_threat_patterns(self, alerts: List[SecurityAlert]) -> List[ThreatPattern]:
        """
        Identify recurring threat patterns from security alerts.
        
        Args:
            alerts: List of SecurityAlert objects
            
        Returns:
            List of identified ThreatPattern objects
        """
        patterns = {}
        
        for alert in alerts:
            # Group by alert type and similar indicators
            pattern_key = f"{alert.alert_type}_{alert.severity}"
            
            if pattern_key not in patterns:
                patterns[pattern_key] = {
                    'alerts': [],
                    'indicators': set(),
                    'severity_counts': {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                }
            
            patterns[pattern_key]['alerts'].append(alert)
            patterns[pattern_key]['indicators'].update(alert.threat_indicators)
            # Normalize severity to uppercase
            severity = alert.severity.upper()
            if severity in patterns[pattern_key]['severity_counts']:
                patterns[pattern_key]['severity_counts'][severity] += 1
        
        threat_patterns = []
        for pattern_key, pattern_data in patterns.items():
            if len(pattern_data['alerts']) >= 2:  # Only patterns with multiple occurrences
                alerts_in_pattern = pattern_data['alerts']
                
                pattern = ThreatPattern(
                    pattern_id=f"pattern_{len(threat_patterns)}",
                    pattern_name=pattern_key.replace('_', ' ').title(),
                    frequency=len(alerts_in_pattern),
                    severity_distribution=pattern_data['severity_counts'],
                    first_seen=min(alert.timestamp for alert in alerts_in_pattern),
                    last_seen=max(alert.timestamp for alert in alerts_in_pattern),
                    indicators=list(pattern_data['indicators']),
                    mitigation_recommendations=self._generate_mitigation_recommendations(pattern_key)
                )
                threat_patterns.append(pattern)
        
        return threat_patterns
    
    def _generate_mitigation_recommendations(self, pattern_key: str) -> List[str]:
        """Generate mitigation recommendations based on threat pattern."""
        recommendations = {
            'INTRUSION_CRITICAL': [
                'Implement network segmentation',
                'Enable advanced threat detection',
                'Review access controls immediately'
            ],
            'MALWARE_HIGH': [
                'Update antivirus signatures',
                'Isolate affected systems',
                'Scan all connected devices'
            ],
            'POLICY_VIOLATION_MEDIUM': [
                'Review and update security policies',
                'Provide additional user training',
                'Implement automated policy enforcement'
            ],
            'ANOMALY_LOW': [
                'Monitor for pattern escalation',
                'Review baseline configurations',
                'Update anomaly detection rules'
            ]
        }
        
        return recommendations.get(pattern_key, ['Review security posture', 'Monitor for escalation'])
    
    def calculate_security_metrics(self, alerts: List[SecurityAlert]) -> SecurityMetrics:
        """
        Calculate comprehensive security metrics for dashboard visualization.
        
        Args:
            alerts: List of SecurityAlert objects
            
        Returns:
            SecurityMetrics object with calculated values
        """
        if not alerts:
            return SecurityMetrics(
                total_alerts=0,
                critical_alerts=0,
                resolved_alerts=0,
                false_positives=0,
                mean_resolution_time=0.0,
                threat_patterns_detected=0,
                security_score=100.0,
                trend_direction='STABLE'
            )
        
        total_alerts = len(alerts)
        critical_alerts = len([a for a in alerts if a.severity == 'CRITICAL'])
        resolved_alerts = len([a for a in alerts if a.status == 'RESOLVED'])
        false_positives = len([a for a in alerts if a.status == 'FALSE_POSITIVE'])
        
        # Calculate mean resolution time (simulated)
        resolved = [a for a in alerts if a.status == 'RESOLVED']
        mean_resolution_time = sum(a.confidence_score * 24 for a in resolved) / len(resolved) if resolved else 0.0
        
        # Identify threat patterns
        threat_patterns = self.identify_threat_patterns(alerts)
        threat_patterns_detected = len(threat_patterns)
        
        # Calculate security score (0-100)
        security_score = max(0, 100 - (critical_alerts * 10) - (len(alerts) * 0.5))
        
        # Determine trend direction (simplified)
        recent_alerts = [a for a in alerts if a.timestamp > datetime.now() - timedelta(days=7)]
        older_alerts = [a for a in alerts if a.timestamp <= datetime.now() - timedelta(days=7)]
        
        if len(recent_alerts) > len(older_alerts):
            trend_direction = 'DEGRADING'
        elif len(recent_alerts) < len(older_alerts):
            trend_direction = 'IMPROVING'
        else:
            trend_direction = 'STABLE'
        
        return SecurityMetrics(
            total_alerts=total_alerts,
            critical_alerts=critical_alerts,
            resolved_alerts=resolved_alerts,
            false_positives=false_positives,
            mean_resolution_time=mean_resolution_time,
            threat_patterns_detected=threat_patterns_detected,
            security_score=security_score,
            trend_direction=trend_direction
        )
    
    def generate_dashboard_data(self) -> Dict[str, Any]:
        """
        Generate comprehensive dashboard data for visualization.
        
        Returns:
            Dictionary containing all dashboard data
        """
        alerts = self.analyze_security_alerts()
        threat_patterns = self.identify_threat_patterns(alerts)
        metrics = self.calculate_security_metrics(alerts)
        
        return {
            'alerts': [asdict(alert) for alert in alerts],
            'threat_patterns': [asdict(pattern) for pattern in threat_patterns],
            'metrics': asdict(metrics),
            'timestamp': datetime.now().isoformat(),
            'data_sources': {
                'security_events': len(self.security_events),
                'network_traffic': len(self.network_traffic),
                'access_logs': len(self.access_logs)
            }
        }

class InteractiveDemoWorkflow:
    """
    Interactive demonstration workflow that showcases end-to-end analysis capabilities.
    """
    
    def __init__(self):
        self.analyzer = SecurityAlertAnalyzer()
        self.logger = logging.getLogger(__name__)
    
    def run_demo_scenario(self, scenario_name: str) -> Dict[str, Any]:
        """
        Run a specific demo scenario.
        
        Args:
            scenario_name: Name of the scenario to run
            
        Returns:
            Dictionary containing scenario results
        """
        scenarios = {
            'advanced_persistent_threat': self._demo_apt_scenario,
            'insider_threat': self._demo_insider_threat_scenario,
            'malware_outbreak': self._demo_malware_scenario,
            'policy_violations': self._demo_policy_violation_scenario
        }
        
        if scenario_name not in scenarios:
            raise ValueError(f"Unknown scenario: {scenario_name}")
        
        return scenarios[scenario_name]()
    
    def _demo_apt_scenario(self) -> Dict[str, Any]:
        """Demonstrate Advanced Persistent Threat detection and analysis."""
        return {
            'scenario': 'Advanced Persistent Threat',
            'description': 'Simulated APT attack with lateral movement and data exfiltration',
            'timeline': [
                {'time': '2024-01-01T09:00:00', 'event': 'Initial compromise via spear phishing'},
                {'time': '2024-01-01T10:30:00', 'event': 'Privilege escalation detected'},
                {'time': '2024-01-01T14:15:00', 'event': 'Lateral movement to critical systems'},
                {'time': '2024-01-01T16:45:00', 'event': 'Data exfiltration attempt blocked'}
            ],
            'analysis_results': self.analyzer.generate_dashboard_data(),
            'recommendations': [
                'Implement zero-trust architecture',
                'Enhance email security controls',
                'Deploy advanced endpoint detection',
                'Conduct security awareness training'
            ]
        }
    
    def _demo_insider_threat_scenario(self) -> Dict[str, Any]:
        """Demonstrate insider threat detection and analysis."""
        return {
            'scenario': 'Insider Threat',
            'description': 'Malicious insider accessing unauthorized data',
            'timeline': [
                {'time': '2024-01-02T08:00:00', 'event': 'Unusual access pattern detected'},
                {'time': '2024-01-02T11:30:00', 'event': 'Access to sensitive data outside normal hours'},
                {'time': '2024-01-02T15:20:00', 'event': 'Large data download flagged'},
                {'time': '2024-01-02T17:00:00', 'event': 'Account suspended pending investigation'}
            ],
            'analysis_results': self.analyzer.generate_dashboard_data(),
            'recommendations': [
                'Implement user behavior analytics',
                'Enforce least privilege access',
                'Monitor data access patterns',
                'Regular access reviews'
            ]
        }
    
    def _demo_malware_scenario(self) -> Dict[str, Any]:
        """Demonstrate malware outbreak detection and response."""
        return {
            'scenario': 'Malware Outbreak',
            'description': 'Ransomware spreading across network infrastructure',
            'timeline': [
                {'time': '2024-01-03T07:30:00', 'event': 'Suspicious file execution detected'},
                {'time': '2024-01-03T08:15:00', 'event': 'Encryption activity on multiple hosts'},
                {'time': '2024-01-03T09:00:00', 'event': 'Network isolation initiated'},
                {'time': '2024-01-03T12:00:00', 'event': 'Recovery from backups completed'}
            ],
            'analysis_results': self.analyzer.generate_dashboard_data(),
            'recommendations': [
                'Update endpoint protection',
                'Implement network segmentation',
                'Regular backup testing',
                'Incident response plan review'
            ]
        }
    
    def _demo_policy_violation_scenario(self) -> Dict[str, Any]:
        """Demonstrate policy violation detection and analysis."""
        return {
            'scenario': 'Policy Violations',
            'description': 'Multiple security policy violations detected',
            'timeline': [
                {'time': '2024-01-04T09:00:00', 'event': 'Unauthorized software installation'},
                {'time': '2024-01-04T11:30:00', 'event': 'Weak password policy violation'},
                {'time': '2024-01-04T14:00:00', 'event': 'Unauthorized data sharing detected'},
                {'time': '2024-01-04T16:30:00', 'event': 'Policy enforcement actions taken'}
            ],
            'analysis_results': self.analyzer.generate_dashboard_data(),
            'recommendations': [
                'Strengthen policy enforcement',
                'Automated compliance monitoring',
                'Regular policy training',
                'Implement technical controls'
            ]
        }

def main():
    """Main function for testing the security dashboard."""
    logging.basicConfig(level=logging.INFO)
    
    # Initialize the security alert analyzer
    analyzer = SecurityAlertAnalyzer()
    
    # Generate dashboard data
    dashboard_data = analyzer.generate_dashboard_data()
    
    print("=== Security Dashboard Demo ===")
    print(f"Total Alerts: {dashboard_data['metrics']['total_alerts']}")
    print(f"Critical Alerts: {dashboard_data['metrics']['critical_alerts']}")
    print(f"Security Score: {dashboard_data['metrics']['security_score']:.1f}")
    print(f"Threat Patterns: {dashboard_data['metrics']['threat_patterns_detected']}")
    print(f"Trend: {dashboard_data['metrics']['trend_direction']}")
    
    # Run interactive demo
    demo = InteractiveDemoWorkflow()
    
    print("\n=== Demo Scenarios ===")
    scenarios = ['advanced_persistent_threat', 'insider_threat', 'malware_outbreak', 'policy_violations']
    
    for scenario in scenarios:
        result = demo.run_demo_scenario(scenario)
        print(f"\nScenario: {result['scenario']}")
        print(f"Description: {result['description']}")
        print(f"Recommendations: {len(result['recommendations'])} items")

if __name__ == "__main__":
    main()