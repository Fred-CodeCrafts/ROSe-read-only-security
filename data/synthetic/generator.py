"""
Synthetic Data Generator for AI Cybersecurity Platform

This module generates realistic but completely synthetic data for testing,
development, and demonstration purposes. All generated data is fake and
should never contain real personal information.

Requirements: 2.9 - Synthetic data validation
"""

import json
import csv
import random
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from faker import Faker
from faker.providers import internet, company, person, date_time, misc
import ipaddress
import hashlib
import secrets

# Initialize Faker with security-focused providers
fake = Faker()
fake.add_provider(internet)
fake.add_provider(company)
fake.add_provider(person)
fake.add_provider(date_time)
fake.add_provider(misc)

class CybersecurityDataGenerator:
    """
    Generates synthetic cybersecurity data for analysis and testing.
    
    All data is completely synthetic and safe for development/testing.
    Validates that no real data patterns are accidentally included.
    """
    
    def __init__(self, seed: Optional[int] = None):
        """Initialize generator with optional seed for reproducible data."""
        if seed:
            Faker.seed(seed)
            random.seed(seed)
        
        # Synthetic company names for testing
        self.synthetic_companies = [
            "CyberCorp Industries", "SecureTest LLC", "MockData Systems",
            "FakeNet Solutions", "SyntheticSec Inc", "TestGuard Corp",
            "DevSecure Ltd", "MockCyber Group", "FakeShield Systems"
        ]
        
        # Synthetic domains for testing
        self.synthetic_domains = [
            "example.com", "test.local", "mock-company.dev",
            "synthetic-corp.test", "fake-security.example",
            "dev-environment.local", "test-network.mock"
        ]
    
    def generate_synthetic_users(self, count: int = 100) -> List[Dict[str, Any]]:
        """Generate synthetic user data for security analysis testing."""
        users = []
        
        for _ in range(count):
            user = {
                "user_id": str(uuid.uuid4()),
                "username": fake.user_name(),
                "email": fake.email(),
                "full_name": fake.name(),
                "department": fake.random_element([
                    "Engineering", "Security", "Operations", "Marketing",
                    "Sales", "HR", "Finance", "Legal", "Support"
                ]),
                "role": fake.random_element([
                    "Developer", "Security Analyst", "DevOps Engineer",
                    "Manager", "Director", "Analyst", "Specialist"
                ]),
                "created_at": fake.date_time_between(start_date="-2y", end_date="now").isoformat(),
                "last_login": fake.date_time_between(start_date="-30d", end_date="now").isoformat(),
                "is_active": fake.boolean(chance_of_getting_true=85),
                "security_clearance": fake.random_element([
                    "Public", "Internal", "Confidential", "Restricted"
                ]),
                "synthetic_flag": True  # Always mark as synthetic
            }
            users.append(user)
        
        return users
    
    def generate_security_events(self, count: int = 500) -> List[Dict[str, Any]]:
        """Generate synthetic security events for SIEM analysis testing."""
        events = []
        
        event_types = [
            "login_attempt", "file_access", "network_connection",
            "privilege_escalation", "data_export", "system_change",
            "authentication_failure", "suspicious_activity"
        ]
        
        severity_levels = ["low", "medium", "high", "critical"]
        
        for _ in range(count):
            event = {
                "event_id": str(uuid.uuid4()),
                "timestamp": fake.date_time_between(start_date="-7d", end_date="now").isoformat(),
                "event_type": fake.random_element(event_types),
                "severity": fake.random_element(severity_levels),
                "source_ip": str(ipaddress.IPv4Address(fake.ipv4_private())),
                "destination_ip": str(ipaddress.IPv4Address(fake.ipv4_private())),
                "user_agent": fake.user_agent(),
                "username": fake.user_name(),
                "resource": fake.file_path(),
                "action": fake.random_element([
                    "read", "write", "execute", "delete", "create", "modify"
                ]),
                "result": fake.random_element(["success", "failure", "blocked"]),
                "details": {
                    "bytes_transferred": fake.random_int(min=0, max=1000000),
                    "duration_ms": fake.random_int(min=1, max=5000),
                    "protocol": fake.random_element(["HTTP", "HTTPS", "SSH", "FTP", "SMTP"])
                },
                "synthetic_flag": True
            }
            events.append(event)
        
        return events
    
    def generate_network_traffic(self, count: int = 1000) -> List[Dict[str, Any]]:
        """Generate synthetic network traffic data for analysis."""
        traffic = []
        
        for _ in range(count):
            record = {
                "flow_id": str(uuid.uuid4()),
                "timestamp": fake.date_time_between(start_date="-1d", end_date="now").isoformat(),
                "source_ip": str(ipaddress.IPv4Address(fake.ipv4_private())),
                "source_port": fake.random_int(min=1024, max=65535),
                "destination_ip": str(ipaddress.IPv4Address(fake.ipv4_private())),
                "destination_port": fake.random_int(min=1, max=65535),
                "protocol": fake.random_element(["TCP", "UDP", "ICMP"]),
                "bytes_sent": fake.random_int(min=64, max=1500),
                "bytes_received": fake.random_int(min=64, max=1500),
                "packets_sent": fake.random_int(min=1, max=100),
                "packets_received": fake.random_int(min=1, max=100),
                "duration": fake.random_int(min=1, max=3600),
                "flags": fake.random_element(["SYN", "ACK", "FIN", "RST", "PSH"]),
                "synthetic_flag": True
            }
            traffic.append(record)
        
        return traffic
    
    def generate_vulnerability_data(self, count: int = 50) -> List[Dict[str, Any]]:
        """Generate synthetic vulnerability data for security analysis."""
        vulnerabilities = []
        
        cve_patterns = ["CVE-2023-{:04d}", "CVE-2024-{:04d}"]
        
        for _ in range(count):
            vuln = {
                "vulnerability_id": str(uuid.uuid4()),
                "cve_id": fake.random_element(cve_patterns).format(fake.random_int(min=1, max=9999)),
                "title": fake.catch_phrase() + " Vulnerability",
                "description": fake.text(max_nb_chars=200),
                "severity": fake.random_element(["Low", "Medium", "High", "Critical"]),
                "cvss_score": round(random.uniform(0.1, 10.0), 1),
                "affected_systems": [
                    fake.random_element(self.synthetic_companies) + " " + fake.random_element([
                        "Web Server", "Database", "Application", "Network Device"
                    ]) for _ in range(fake.random_int(min=1, max=5))
                ],
                "discovery_date": fake.date_between(start_date="-1y", end_date="now").isoformat(),
                "patch_available": fake.boolean(chance_of_getting_true=70),
                "exploit_available": fake.boolean(chance_of_getting_true=30),
                "synthetic_flag": True
            }
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def generate_access_logs(self, count: int = 2000) -> List[Dict[str, Any]]:
        """Generate synthetic access logs for data governance analysis."""
        logs = []
        
        for _ in range(count):
            log = {
                "log_id": str(uuid.uuid4()),
                "timestamp": fake.date_time_between(start_date="-30d", end_date="now").isoformat(),
                "user_id": str(uuid.uuid4()),
                "username": fake.user_name(),
                "resource": fake.file_path(),
                "action": fake.random_element([
                    "read", "write", "delete", "create", "list", "download", "upload"
                ]),
                "ip_address": str(ipaddress.IPv4Address(fake.ipv4_private())),
                "user_agent": fake.user_agent(),
                "response_code": fake.random_element([200, 201, 400, 401, 403, 404, 500]),
                "bytes_transferred": fake.random_int(min=0, max=10000000),
                "duration_ms": fake.random_int(min=1, max=30000),
                "data_classification": fake.random_element([
                    "Public", "Internal", "Confidential", "Restricted"
                ]),
                "synthetic_flag": True
            }
            logs.append(log)
        
        return logs
    
    def validate_synthetic_data(self, data: List[Dict[str, Any]]) -> bool:
        """
        Validate that data contains only synthetic information.
        
        Returns False if any real data patterns are detected.
        """
        import re
        
        # Check that all records have synthetic_flag
        for record in data:
            if not record.get('synthetic_flag', False):
                print(f"Validation failed: Record missing synthetic_flag")
                return False
        
        # Convert data to string for pattern checking
        data_str = json.dumps(data, default=str).lower()
        
        # Define patterns for real data that should NOT appear
        # Only check for specific real data leaks that indicate actual personal info
        forbidden_patterns = [
            # Explicit real data indicators
            r'real[_\s]+email', r'production[_\s]+data', r'live[_\s]+data',
            r'customer[_\s]+data', r'personal[_\s]+information',
            # Social security numbers
            r'\b\d{3}-\d{2}-\d{4}\b',
            # Credit card patterns (basic check)
            r'\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        ]
        
        for pattern in forbidden_patterns:
            if re.search(pattern, data_str):
                print(f"Validation failed: Found forbidden real data pattern: {pattern}")
                return False
        
        return True
    
    def save_to_json(self, data: List[Dict[str, Any]], filename: str) -> None:
        """Save synthetic data to JSON file with validation."""
        if not self.validate_synthetic_data(data):
            raise ValueError("Data validation failed - potential real data detected")
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def save_to_csv(self, data: List[Dict[str, Any]], filename: str) -> None:
        """Save synthetic data to CSV file with validation."""
        if not self.validate_synthetic_data(data):
            raise ValueError("Data validation failed - potential real data detected")
        
        if not data:
            return
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)

def main():
    """Generate sample synthetic datasets for development and testing."""
    generator = CybersecurityDataGenerator(seed=42)  # Reproducible data
    
    print("[*] Generating synthetic cybersecurity data...")
    
    # Generate datasets
    users = generator.generate_synthetic_users(100)
    events = generator.generate_security_events(500)
    traffic = generator.generate_network_traffic(1000)
    vulnerabilities = generator.generate_vulnerability_data(50)
    access_logs = generator.generate_access_logs(2000)
    
    # Save to files
    generator.save_to_json(users, "data/synthetic/users.json")
    generator.save_to_json(events, "data/synthetic/security_events.json")
    generator.save_to_json(traffic, "data/synthetic/network_traffic.json")
    generator.save_to_json(vulnerabilities, "data/synthetic/vulnerabilities.json")
    generator.save_to_json(access_logs, "data/synthetic/access_logs.json")
    
    # Also save as CSV for analysis tools
    generator.save_to_csv(users, "data/synthetic/users.csv")
    generator.save_to_csv(events, "data/synthetic/security_events.csv")
    generator.save_to_csv(traffic, "data/synthetic/network_traffic.csv")
    generator.save_to_csv(vulnerabilities, "data/synthetic/vulnerabilities.csv")
    generator.save_to_csv(access_logs, "data/synthetic/access_logs.csv")
    
    print("[+] Synthetic data generation complete!")
    print(f"   - {len(users)} synthetic users")
    print(f"   - {len(events)} synthetic security events")
    print(f"   - {len(traffic)} synthetic network traffic records")
    print(f"   - {len(vulnerabilities)} synthetic vulnerabilities")
    print(f"   - {len(access_logs)} synthetic access logs")
    print("\n[*] Files saved to data/synthetic/")
    print("[!] All data is synthetic and safe for development/testing")

if __name__ == "__main__":
    main()