"""
Mock Data Scenarios for Cybersecurity Use Case Demonstration

This module provides realistic mock data scenarios that simulate various
cybersecurity threats and incidents for demonstration purposes.
"""

import json
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
import uuid

@dataclass
class MockSecurityEvent:
    """Mock security event for demonstration purposes."""
    event_id: str
    timestamp: str
    severity: str
    event_type: str
    source_ip: str
    target_ip: str
    description: str
    indicators: List[str]
    affected_assets: List[str]
    confidence: float

@dataclass
class MockNetworkTraffic:
    """Mock network traffic data for analysis."""
    session_id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    flags: List[str]

@dataclass
class MockAccessLog:
    """Mock access log entry for analysis."""
    log_id: str
    timestamp: str
    user_id: str
    resource: str
    action: str
    result: str
    source_ip: str
    user_agent: str

class MockDataGenerator:
    """
    Generates realistic mock data for cybersecurity demonstration scenarios.
    """
    
    def __init__(self):
        # Common IP ranges for simulation
        self.internal_ips = [
            "10.0.0.{}".format(i) for i in range(1, 255)
        ] + [
            "192.168.1.{}".format(i) for i in range(1, 255)
        ]
        
        self.external_ips = [
            "203.0.113.{}".format(i) for i in range(1, 255)
        ] + [
            "198.51.100.{}".format(i) for i in range(1, 255)
        ]
        
        # Common threat indicators
        self.threat_indicators = [
            "port_scan", "brute_force", "malware_signature", "suspicious_traffic",
            "privilege_escalation", "lateral_movement", "data_exfiltration",
            "command_injection", "sql_injection", "xss_attempt", "ddos_pattern",
            "unusual_login", "failed_authentication", "unauthorized_access"
        ]
        
        # Asset names
        self.assets = [
            "web-server-01", "web-server-02", "database-01", "database-02",
            "file-server-01", "mail-server-01", "dns-server-01", "proxy-server-01",
            "workstation-001", "workstation-002", "laptop-001", "mobile-device-001"
        ]
        
        # User IDs
        self.users = [
            "alice.smith", "bob.jones", "charlie.brown", "diana.prince",
            "eve.adams", "frank.miller", "grace.hopper", "henry.ford",
            "admin", "service_account", "backup_user", "guest"
        ]
        
        # Resources
        self.resources = [
            "/api/users", "/api/admin", "/database/customers", "/files/confidential",
            "/login", "/dashboard", "/reports", "/settings", "/backup",
            "/logs", "/monitoring", "/config"
        ]
    
    def generate_apt_scenario(self, duration_hours: int = 24) -> Dict[str, List[Dict]]:
        """
        Generate Advanced Persistent Threat scenario data.
        
        Args:
            duration_hours: Duration of the attack scenario in hours
            
        Returns:
            Dictionary containing security events, network traffic, and access logs
        """
        start_time = datetime.now() - timedelta(hours=duration_hours)
        events = []
        traffic = []
        access_logs = []
        
        # Phase 1: Initial Compromise (spear phishing)
        phase1_time = start_time
        events.append(MockSecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=phase1_time.isoformat(),
            severity="HIGH",
            event_type="MALWARE",
            source_ip=random.choice(self.external_ips),
            target_ip=random.choice(self.internal_ips),
            description="Spear phishing email with malicious attachment detected",
            indicators=["malware_signature", "suspicious_email"],
            affected_assets=["workstation-001"],
            confidence=0.85
        ))
        
        # Phase 2: Privilege Escalation
        phase2_time = phase1_time + timedelta(hours=2)
        events.append(MockSecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=phase2_time.isoformat(),
            severity="CRITICAL",
            event_type="INTRUSION",
            source_ip=self.internal_ips[0],
            target_ip=self.internal_ips[1],
            description="Privilege escalation attempt detected",
            indicators=["privilege_escalation", "unusual_process"],
            affected_assets=["workstation-001", "domain-controller"],
            confidence=0.92
        ))
        
        # Phase 3: Lateral Movement
        phase3_time = phase2_time + timedelta(hours=4)
        for i in range(3):
            events.append(MockSecurityEvent(
                event_id=str(uuid.uuid4()),
                timestamp=(phase3_time + timedelta(minutes=i*30)).isoformat(),
                severity="HIGH",
                event_type="INTRUSION",
                source_ip=random.choice(self.internal_ips[:5]),
                target_ip=random.choice(self.internal_ips[5:10]),
                description=f"Lateral movement detected - compromised system {i+1}",
                indicators=["lateral_movement", "suspicious_traffic"],
                affected_assets=[f"server-0{i+1}"],
                confidence=0.78
            ))
        
        # Phase 4: Data Exfiltration
        phase4_time = phase3_time + timedelta(hours=6)
        events.append(MockSecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=phase4_time.isoformat(),
            severity="CRITICAL",
            event_type="POLICY_VIOLATION",
            source_ip=self.internal_ips[2],
            target_ip=random.choice(self.external_ips),
            description="Large data transfer to external IP detected",
            indicators=["data_exfiltration", "unusual_traffic"],
            affected_assets=["database-01", "file-server-01"],
            confidence=0.95
        ))
        
        # Generate corresponding network traffic
        for event in events:
            traffic.append(MockNetworkTraffic(
                session_id=str(uuid.uuid4()),
                timestamp=event.timestamp,
                source_ip=event.source_ip,
                destination_ip=event.target_ip,
                source_port=random.randint(1024, 65535),
                destination_port=random.choice([80, 443, 22, 3389, 445]),
                protocol=random.choice(["TCP", "UDP"]),
                bytes_sent=random.randint(1000, 1000000),
                bytes_received=random.randint(500, 500000),
                flags=["SYN", "ACK"] if random.random() > 0.5 else ["FIN", "RST"]
            ))
        
        # Generate access logs
        for i in range(20):
            log_time = start_time + timedelta(minutes=random.randint(0, duration_hours*60))
            access_logs.append(MockAccessLog(
                log_id=str(uuid.uuid4()),
                timestamp=log_time.isoformat(),
                user_id=random.choice(self.users),
                resource=random.choice(self.resources),
                action=random.choice(["GET", "POST", "PUT", "DELETE"]),
                result=random.choice(["SUCCESS", "FAILED", "BLOCKED"]),
                source_ip=random.choice(self.internal_ips + self.external_ips),
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            ))
        
        return {
            "security_events": [asdict(event) for event in events],
            "network_traffic": [asdict(traffic_item) for traffic_item in traffic],
            "access_logs": [asdict(log) for log in access_logs]
        }
    
    def generate_insider_threat_scenario(self, duration_days: int = 7) -> Dict[str, List[Dict]]:
        """
        Generate insider threat scenario data.
        
        Args:
            duration_days: Duration of the insider threat scenario in days
            
        Returns:
            Dictionary containing security events, network traffic, and access logs
        """
        start_time = datetime.now() - timedelta(days=duration_days)
        events = []
        traffic = []
        access_logs = []
        
        # Malicious insider user
        insider_user = "eve.adams"
        insider_ip = self.internal_ips[10]
        
        # Pattern 1: Unusual access times
        for day in range(duration_days):
            # Late night access
            night_time = start_time + timedelta(days=day, hours=23, minutes=random.randint(0, 59))
            events.append(MockSecurityEvent(
                event_id=str(uuid.uuid4()),
                timestamp=night_time.isoformat(),
                severity="MEDIUM",
                event_type="ANOMALY",
                source_ip=insider_ip,
                target_ip=self.internal_ips[0],
                description=f"Unusual access time detected for user {insider_user}",
                indicators=["unusual_login", "off_hours_access"],
                affected_assets=["file-server-01"],
                confidence=0.65
            ))
            
            # Corresponding access log
            access_logs.append(MockAccessLog(
                log_id=str(uuid.uuid4()),
                timestamp=night_time.isoformat(),
                user_id=insider_user,
                resource="/files/confidential",
                action="GET",
                result="SUCCESS",
                source_ip=insider_ip,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            ))
        
        # Pattern 2: Large data downloads
        download_time = start_time + timedelta(days=duration_days-2, hours=15)
        events.append(MockSecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=download_time.isoformat(),
            severity="HIGH",
            event_type="POLICY_VIOLATION",
            source_ip=insider_ip,
            target_ip=self.internal_ips[1],
            description="Large data download detected - potential data theft",
            indicators=["data_exfiltration", "unusual_download"],
            affected_assets=["database-01"],
            confidence=0.88
        ))
        
        # Pattern 3: Access to unauthorized resources
        for i in range(5):
            unauthorized_time = start_time + timedelta(days=random.randint(0, duration_days-1), 
                                                    hours=random.randint(9, 17))
            events.append(MockSecurityEvent(
                event_id=str(uuid.uuid4()),
                timestamp=unauthorized_time.isoformat(),
                severity="MEDIUM",
                event_type="POLICY_VIOLATION",
                source_ip=insider_ip,
                target_ip=self.internal_ips[2],
                description=f"Unauthorized resource access attempt {i+1}",
                indicators=["unauthorized_access", "policy_violation"],
                affected_assets=["admin-panel"],
                confidence=0.72
            ))
        
        return {
            "security_events": [asdict(event) for event in events],
            "network_traffic": [asdict(traffic_item) for traffic_item in traffic],
            "access_logs": [asdict(log) for log in access_logs]
        }
    
    def generate_malware_outbreak_scenario(self, duration_hours: int = 12) -> Dict[str, List[Dict]]:
        """
        Generate malware outbreak scenario data.
        
        Args:
            duration_hours: Duration of the malware outbreak in hours
            
        Returns:
            Dictionary containing security events, network traffic, and access logs
        """
        start_time = datetime.now() - timedelta(hours=duration_hours)
        events = []
        traffic = []
        access_logs = []
        
        # Initial infection
        patient_zero = self.internal_ips[0]
        infection_time = start_time
        
        events.append(MockSecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=infection_time.isoformat(),
            severity="CRITICAL",
            event_type="MALWARE",
            source_ip=random.choice(self.external_ips),
            target_ip=patient_zero,
            description="Ransomware infection detected - patient zero",
            indicators=["malware_signature", "ransomware", "file_encryption"],
            affected_assets=["workstation-001"],
            confidence=0.98
        ))
        
        # Spread to other systems
        infected_systems = [patient_zero]
        for hour in range(1, min(duration_hours, 8)):
            spread_time = start_time + timedelta(hours=hour)
            new_victim = random.choice([ip for ip in self.internal_ips if ip not in infected_systems])
            infected_systems.append(new_victim)
            
            events.append(MockSecurityEvent(
                event_id=str(uuid.uuid4()),
                timestamp=spread_time.isoformat(),
                severity="CRITICAL",
                event_type="MALWARE",
                source_ip=random.choice(infected_systems[:-1]),
                target_ip=new_victim,
                description=f"Ransomware spread detected - system {len(infected_systems)}",
                indicators=["malware_signature", "ransomware", "lateral_movement"],
                affected_assets=[f"system-{len(infected_systems):03d}"],
                confidence=0.95
            ))
        
        # Network isolation events
        isolation_time = start_time + timedelta(hours=duration_hours//2)
        events.append(MockSecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=isolation_time.isoformat(),
            severity="HIGH",
            event_type="RESPONSE",
            source_ip="0.0.0.0",
            target_ip="0.0.0.0",
            description="Network isolation initiated - containing malware spread",
            indicators=["incident_response", "network_isolation"],
            affected_assets=["network_infrastructure"],
            confidence=1.0
        ))
        
        return {
            "security_events": [asdict(event) for event in events],
            "network_traffic": [asdict(traffic_item) for traffic_item in traffic],
            "access_logs": [asdict(log) for log in access_logs]
        }
    
    def generate_policy_violation_scenario(self, duration_days: int = 14) -> Dict[str, List[Dict]]:
        """
        Generate policy violation scenario data.
        
        Args:
            duration_days: Duration of the policy violation scenario in days
            
        Returns:
            Dictionary containing security events, network traffic, and access logs
        """
        start_time = datetime.now() - timedelta(days=duration_days)
        events = []
        traffic = []
        access_logs = []
        
        # Various policy violations
        violation_types = [
            ("Unauthorized software installation", "SOFTWARE_POLICY"),
            ("Weak password detected", "PASSWORD_POLICY"),
            ("Unauthorized data sharing", "DATA_POLICY"),
            ("Excessive privilege usage", "ACCESS_POLICY"),
            ("Unencrypted data transmission", "ENCRYPTION_POLICY")
        ]
        
        for day in range(duration_days):
            # Generate 1-3 violations per day
            num_violations = random.randint(1, 3)
            
            for _ in range(num_violations):
                violation_time = start_time + timedelta(
                    days=day, 
                    hours=random.randint(8, 18), 
                    minutes=random.randint(0, 59)
                )
                
                violation_desc, violation_type = random.choice(violation_types)
                
                events.append(MockSecurityEvent(
                    event_id=str(uuid.uuid4()),
                    timestamp=violation_time.isoformat(),
                    severity=random.choice(["MEDIUM", "LOW"]),
                    event_type="POLICY_VIOLATION",
                    source_ip=random.choice(self.internal_ips),
                    target_ip=random.choice(self.internal_ips),
                    description=violation_desc,
                    indicators=["policy_violation", violation_type.lower()],
                    affected_assets=[random.choice(self.assets)],
                    confidence=0.80
                ))
        
        return {
            "security_events": [asdict(event) for event in events],
            "network_traffic": [asdict(traffic_item) for traffic_item in traffic],
            "access_logs": [asdict(log) for log in access_logs]
        }
    
    def save_scenario_data(self, scenario_name: str, scenario_data: Dict[str, List[Dict]], 
                          output_dir: str = "data/synthetic") -> Dict[str, str]:
        """
        Save scenario data to files.
        
        Args:
            scenario_name: Name of the scenario
            scenario_data: Generated scenario data
            output_dir: Output directory for files
            
        Returns:
            Dictionary mapping data type to file path
        """
        from pathlib import Path
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        file_paths = {}
        
        for data_type, data_list in scenario_data.items():
            filename = f"{scenario_name}_{data_type}.json"
            file_path = output_path / filename
            
            with open(file_path, 'w') as f:
                json.dump(data_list, f, indent=2)
            
            file_paths[data_type] = str(file_path)
        
        return file_paths

def main():
    """Generate all mock data scenarios for demonstration."""
    generator = MockDataGenerator()
    
    scenarios = {
        "apt_attack": generator.generate_apt_scenario(24),
        "insider_threat": generator.generate_insider_threat_scenario(7),
        "malware_outbreak": generator.generate_malware_outbreak_scenario(12),
        "policy_violations": generator.generate_policy_violation_scenario(14)
    }
    
    print("Generating mock data scenarios...")
    
    for scenario_name, scenario_data in scenarios.items():
        file_paths = generator.save_scenario_data(scenario_name, scenario_data)
        print(f"\n{scenario_name.replace('_', ' ').title()} Scenario:")
        for data_type, file_path in file_paths.items():
            print(f"  - {data_type}: {file_path}")
    
    print("\nMock data generation complete!")

if __name__ == "__main__":
    main()