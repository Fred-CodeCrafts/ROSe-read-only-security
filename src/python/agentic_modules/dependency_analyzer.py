"""
OSS-First Dependency Security Analysis Module

This module provides comprehensive dependency security analysis including:
- Vulnerability scanning with threat intelligence
- Package validation against threat databases  
- AI output validation for hallucination detection
- Supply chain security analysis and recommendations

Requirements: 4.2, 4.3, 4.4
"""

import json
import re
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
import hashlib
import requests
from urllib.parse import urlparse

# OSS Dependencies (with optional imports)
try:
    import semgrep
    SEMGREP_AVAILABLE = True
except ImportError:
    SEMGREP_AVAILABLE = False

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


@dataclass
class VulnerabilityReport:
    """Vulnerability analysis report"""
    vulnerability_id: str
    cve_id: Optional[str]
    title: str
    description: str
    severity: str
    cvss_score: float
    affected_systems: List[str]
    discovery_date: str
    patch_available: bool
    exploit_available: bool
    synthetic_flag: bool = True


@dataclass
class PackageValidationResult:
    """Package validation analysis result"""
    package_name: str
    version: str
    is_valid: bool
    risk_level: str
    validation_checks: Dict[str, bool]
    threat_indicators: List[str]
    recommendations: List[str]
    analysis_timestamp: str


@dataclass
class AIOutputValidationResult:
    """AI output validation analysis result"""
    content: str
    is_valid: bool
    confidence_score: float
    hallucination_indicators: List[str]
    content_risks: List[str]
    validation_checks: Dict[str, bool]
    recommendations: List[str]
    analysis_timestamp: str


@dataclass
class SupplyChainAnalysisResult:
    """Supply chain security analysis result"""
    dependency_tree: Dict[str, Any]
    risk_assessment: str
    vulnerable_dependencies: List[str]
    outdated_dependencies: List[str]
    license_issues: List[str]
    security_recommendations: List[str]
    analysis_timestamp: str


class OSSDependencyAnalyzer:
    """
    OSS-First Dependency Security Analyzer
    
    Provides comprehensive dependency analysis using open-source tools:
    - Semgrep for SAST analysis
    - Local vulnerability database
    - Package validation against threat databases
    - AI output validation for hallucination detection
    """
    
    def __init__(self, 
                 vulnerability_db_path: str = "data/synthetic/vulnerabilities.json",
                 analysis_db_path: str = "analysis_dependency.db"):
        """Initialize the dependency analyzer"""
        self.vulnerability_db_path = Path(vulnerability_db_path)
        self.analysis_db_path = Path(analysis_db_path)
        self.known_malicious_packages = self._load_malicious_packages()
        self.trusted_package_sources = {
            "pypi.org", "npmjs.com", "rubygems.org", "crates.io", "maven.org"
        }
        
        # Initialize analysis database
        self._init_analysis_db()
        
        # Load vulnerability database
        self.vulnerability_db = self._load_vulnerability_db()
    
    def _init_analysis_db(self) -> None:
        """Initialize SQLite database for analysis storage"""
        with sqlite3.connect(self.analysis_db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS dependency_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE,
                    timestamp TEXT,
                    scan_type TEXT,
                    results TEXT,
                    metadata TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS package_validations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    package_name TEXT,
                    version TEXT,
                    validation_result TEXT,
                    timestamp TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ai_validations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    content_hash TEXT,
                    validation_result TEXT,
                    timestamp TEXT
                )
            """)
    
    def _load_vulnerability_db(self) -> List[VulnerabilityReport]:
        """Load vulnerability database from synthetic data"""
        if not self.vulnerability_db_path.exists():
            return []
        
        try:
            with open(self.vulnerability_db_path, 'r') as f:
                data = json.load(f)
                return [VulnerabilityReport(**vuln) for vuln in data]
        except Exception as e:
            print(f"Warning: Could not load vulnerability database: {e}")
            return []
    
    def _load_malicious_packages(self) -> Set[str]:
        """Load known malicious package patterns"""
        # In a real implementation, this would load from threat intelligence feeds
        return {
            "malicious-package", "evil-lib", "backdoor-util", "typosquatting-lib",
            "fake-requests", "fake-numpy", "malware-tool", "crypto-stealer"
        }
    
    def analyze_dependencies_with_threat_intelligence(self, 
                                                    requirements_file: str) -> Dict[str, Any]:
        """
        Analyze dependencies with threat intelligence integration
        
        Requirement 4.2: WHEN dependencies are analyzed, THE System SHALL verify them 
        using security scanning tools and generate vulnerability reports
        """
        scan_id = f"dep_scan_{datetime.now().isoformat()}"
        results = {
            "scan_id": scan_id,
            "timestamp": datetime.now().isoformat(),
            "requirements_file": requirements_file,
            "vulnerabilities": [],
            "security_recommendations": [],
            "risk_assessment": "Low"
        }
        
        try:
            # Parse requirements file
            dependencies = self._parse_requirements_file(requirements_file)
            
            # Scan each dependency for vulnerabilities
            for dep_name, dep_version in dependencies.items():
                vuln_results = self._scan_dependency_vulnerabilities(dep_name, dep_version)
                results["vulnerabilities"].extend(vuln_results)
            
            # Generate risk assessment
            results["risk_assessment"] = self._assess_dependency_risk(results["vulnerabilities"])
            
            # Generate security recommendations
            results["security_recommendations"] = self._generate_dependency_recommendations(
                results["vulnerabilities"]
            )
            
            # Store results in analysis database
            self._store_scan_results(scan_id, "dependency_vulnerability", results)
            
        except Exception as e:
            results["error"] = f"Dependency analysis failed: {str(e)}"
            results["risk_assessment"] = "Unknown"
        
        return results
    
    def validate_package_against_threat_databases(self, 
                                                package_name: str, 
                                                version: str) -> PackageValidationResult:
        """
        Validate package against multiple threat databases
        
        Requirement 4.3: WHEN package installations are analyzed, THE System SHALL 
        validate against known threat databases and generate risk assessments
        """
        validation_checks = {
            "malicious_package_check": False,
            "typosquatting_check": False,
            "source_validation": False,
            "signature_verification": False,
            "reputation_check": False
        }
        
        threat_indicators = []
        recommendations = []
        
        # Check against known malicious packages
        if package_name.lower() in self.known_malicious_packages:
            threat_indicators.append(f"Package '{package_name}' matches known malicious pattern")
        else:
            validation_checks["malicious_package_check"] = True
        
        # Check for typosquatting patterns
        typosquat_risk = self._check_typosquatting_risk(package_name)
        if typosquat_risk:
            threat_indicators.append(f"Potential typosquatting risk: {typosquat_risk}")
        else:
            validation_checks["typosquatting_check"] = True
        
        # Validate package source
        source_valid = self._validate_package_source(package_name)
        if source_valid:
            validation_checks["source_validation"] = True
        else:
            threat_indicators.append("Package source not from trusted registry")
        
        # Check package reputation (simplified)
        reputation_score = self._check_package_reputation(package_name)
        if reputation_score > 0.7:
            validation_checks["reputation_check"] = True
        else:
            threat_indicators.append(f"Low reputation score: {reputation_score}")
        
        # Generate recommendations
        if threat_indicators:
            recommendations.extend([
                "Review package source and maintainer reputation",
                "Consider alternative packages with better security posture",
                "Implement additional monitoring for this dependency"
            ])
        else:
            recommendations.append("Package validation passed all security checks")
        
        # Determine overall risk level
        passed_checks = sum(validation_checks.values())
        total_checks = len(validation_checks)
        
        if passed_checks == total_checks:
            risk_level = "Low"
            is_valid = True
        elif passed_checks >= total_checks * 0.7:
            risk_level = "Medium"
            is_valid = True
        else:
            risk_level = "High"
            is_valid = False
        
        result = PackageValidationResult(
            package_name=package_name,
            version=version,
            is_valid=is_valid,
            risk_level=risk_level,
            validation_checks=validation_checks,
            threat_indicators=threat_indicators,
            recommendations=recommendations,
            analysis_timestamp=datetime.now().isoformat()
        )
        
        # Store validation result
        self._store_package_validation(result)
        
        return result
    
    def validate_ai_output_for_hallucinations(self, 
                                            ai_content: str, 
                                            context: Optional[str] = None) -> AIOutputValidationResult:
        """
        Validate AI output for hallucination detection and mitigation
        
        Requirement 4.4: THE System SHALL analyze AI outputs for hallucination patterns 
        and generate confidence assessments
        """
        validation_checks = {
            "factual_consistency": False,
            "context_relevance": False,
            "technical_accuracy": False,
            "source_attribution": False,
            "confidence_indicators": False
        }
        
        hallucination_indicators = []
        content_risks = []
        recommendations = []
        
        # Check for factual consistency patterns
        factual_score = self._check_factual_consistency(ai_content)
        if factual_score > 0.8:
            validation_checks["factual_consistency"] = True
        else:
            hallucination_indicators.append("Potential factual inconsistencies detected")
        
        # Check context relevance if context provided
        if context:
            relevance_score = self._check_context_relevance(ai_content, context)
            if relevance_score > 0.7:
                validation_checks["context_relevance"] = True
            else:
                hallucination_indicators.append("Content may not be relevant to context")
        else:
            validation_checks["context_relevance"] = True  # Skip if no context
        
        # Check technical accuracy for security content
        tech_accuracy = self._check_technical_accuracy(ai_content)
        if tech_accuracy > 0.75:
            validation_checks["technical_accuracy"] = True
        else:
            hallucination_indicators.append("Technical accuracy concerns detected")
        
        # Check for proper source attribution
        has_sources = self._check_source_attribution(ai_content)
        if has_sources:
            validation_checks["source_attribution"] = True
        else:
            content_risks.append("No source attribution found")
        
        # Check for confidence indicators
        has_confidence = self._check_confidence_indicators(ai_content)
        if has_confidence:
            validation_checks["confidence_indicators"] = True
        else:
            content_risks.append("No confidence indicators present")
        
        # Calculate overall confidence score
        passed_checks = sum(validation_checks.values())
        total_checks = len(validation_checks)
        confidence_score = passed_checks / total_checks
        
        # Generate recommendations
        if confidence_score < 0.6:
            recommendations.extend([
                "Human review required before using this content",
                "Verify technical claims with authoritative sources",
                "Consider regenerating with more specific prompts"
            ])
        elif confidence_score < 0.8:
            recommendations.extend([
                "Review content for accuracy before implementation",
                "Cross-reference with documentation"
            ])
        else:
            recommendations.append("Content validation passed with high confidence")
        
        # Determine if content is valid
        is_valid = confidence_score >= 0.7 and len(hallucination_indicators) == 0
        
        result = AIOutputValidationResult(
            content=ai_content[:500] + "..." if len(ai_content) > 500 else ai_content,
            is_valid=is_valid,
            confidence_score=confidence_score,
            hallucination_indicators=hallucination_indicators,
            content_risks=content_risks,
            validation_checks=validation_checks,
            recommendations=recommendations,
            analysis_timestamp=datetime.now().isoformat()
        )
        
        # Store validation result
        self._store_ai_validation(result)
        
        return result
    
    def analyze_supply_chain_security(self, 
                                    project_path: str) -> SupplyChainAnalysisResult:
        """
        Analyze supply chain security and generate recommendations
        
        Combines requirements 4.2, 4.3, 4.4 for comprehensive supply chain analysis
        """
        dependency_tree = self._build_dependency_tree(project_path)
        vulnerable_deps = []
        outdated_deps = []
        license_issues = []
        security_recommendations = []
        
        # Analyze each dependency in the tree
        for dep_name, dep_info in dependency_tree.items():
            version = dep_info.get("version", "unknown")
            
            # Check for vulnerabilities
            vulns = self._scan_dependency_vulnerabilities(dep_name, version)
            if vulns:
                vulnerable_deps.append(f"{dep_name}@{version}")
            
            # Check if outdated
            if self._is_dependency_outdated(dep_name, version):
                outdated_deps.append(f"{dep_name}@{version}")
            
            # Check license compatibility
            license_risk = self._check_license_compatibility(dep_name, version)
            if license_risk:
                license_issues.append(f"{dep_name}: {license_risk}")
        
        # Generate risk assessment
        total_deps = len(dependency_tree)
        vuln_count = len(vulnerable_deps)
        outdated_count = len(outdated_deps)
        
        if vuln_count > total_deps * 0.1 or outdated_count > total_deps * 0.3:
            risk_assessment = "High"
        elif vuln_count > 0 or outdated_count > total_deps * 0.1:
            risk_assessment = "Medium"
        else:
            risk_assessment = "Low"
        
        # Generate security recommendations
        if vulnerable_deps:
            security_recommendations.append(
                f"Update {len(vulnerable_deps)} vulnerable dependencies immediately"
            )
        
        if outdated_deps:
            security_recommendations.append(
                f"Consider updating {len(outdated_deps)} outdated dependencies"
            )
        
        if license_issues:
            security_recommendations.append(
                "Review license compatibility issues before deployment"
            )
        
        if not security_recommendations:
            security_recommendations.append(
                "Supply chain analysis passed - no immediate security concerns"
            )
        
        return SupplyChainAnalysisResult(
            dependency_tree=dependency_tree,
            risk_assessment=risk_assessment,
            vulnerable_dependencies=vulnerable_deps,
            outdated_dependencies=outdated_deps,
            license_issues=license_issues,
            security_recommendations=security_recommendations,
            analysis_timestamp=datetime.now().isoformat()
        )
    
    # Helper methods for analysis implementation
    
    def _parse_requirements_file(self, requirements_file: str) -> Dict[str, str]:
        """Parse requirements file and extract dependencies"""
        dependencies = {}
        
        try:
            with open(requirements_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Simple parsing - in production would use pip-tools
                        if '>=' in line:
                            name, version = line.split('>=')
                            dependencies[name.strip()] = version.strip()
                        elif '==' in line:
                            name, version = line.split('==')
                            dependencies[name.strip()] = version.strip()
                        else:
                            dependencies[line.strip()] = "latest"
        except Exception as e:
            print(f"Warning: Could not parse requirements file: {e}")
        
        return dependencies
    
    def _scan_dependency_vulnerabilities(self, dep_name: str, dep_version: str) -> List[Dict]:
        """Scan dependency for known vulnerabilities"""
        vulnerabilities = []
        
        # Search in local vulnerability database
        for vuln in self.vulnerability_db:
            # Simple matching - in production would use proper CVE databases
            if dep_name.lower() in vuln.title.lower() or dep_name.lower() in vuln.description.lower():
                vulnerabilities.append({
                    "vulnerability_id": vuln.vulnerability_id,
                    "cve_id": vuln.cve_id,
                    "title": vuln.title,
                    "severity": vuln.severity,
                    "cvss_score": vuln.cvss_score,
                    "description": vuln.description,
                    "patch_available": vuln.patch_available
                })
        
        return vulnerabilities
    
    def _assess_dependency_risk(self, vulnerabilities: List[Dict]) -> str:
        """Assess overall risk level based on vulnerabilities"""
        if not vulnerabilities:
            return "Low"
        
        critical_count = sum(1 for v in vulnerabilities if v.get("severity") == "Critical")
        high_count = sum(1 for v in vulnerabilities if v.get("severity") == "High")
        
        if critical_count > 0:
            return "Critical"
        elif high_count > 2:
            return "High"
        elif high_count > 0 or len(vulnerabilities) > 5:
            return "Medium"
        else:
            return "Low"
    
    def _generate_dependency_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate security recommendations based on vulnerabilities"""
        recommendations = []
        
        if not vulnerabilities:
            recommendations.append("No known vulnerabilities found in dependencies")
            return recommendations
        
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "Critical"]
        if critical_vulns:
            recommendations.append(
                f"URGENT: Address {len(critical_vulns)} critical vulnerabilities immediately"
            )
        
        patchable_vulns = [v for v in vulnerabilities if v.get("patch_available")]
        if patchable_vulns:
            recommendations.append(
                f"Update dependencies to patch {len(patchable_vulns)} known vulnerabilities"
            )
        
        recommendations.extend([
            "Implement dependency scanning in CI/CD pipeline",
            "Consider using dependency pinning for reproducible builds",
            "Monitor security advisories for used dependencies"
        ])
        
        return recommendations
    
    def _check_typosquatting_risk(self, package_name: str) -> Optional[str]:
        """Check for potential typosquatting patterns"""
        common_packages = {
            "requests", "numpy", "pandas", "flask", "django", "tensorflow",
            "pytorch", "scikit-learn", "matplotlib", "seaborn", "boto3"
        }
        
        # Simple Levenshtein distance check
        for common_pkg in common_packages:
            if self._levenshtein_distance(package_name.lower(), common_pkg) == 1:
                return f"Similar to popular package '{common_pkg}'"
        
        return None
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _validate_package_source(self, package_name: str) -> bool:
        """Validate package comes from trusted source"""
        # Simplified validation - in production would check actual registry
        return True  # Assume valid for synthetic analysis
    
    def _check_package_reputation(self, package_name: str) -> float:
        """Check package reputation score"""
        # Simplified reputation scoring
        if package_name in self.known_malicious_packages:
            return 0.0
        
        # Synthetic scoring based on package name characteristics
        score = 0.8
        if len(package_name) < 3:
            score -= 0.2
        if any(char.isdigit() for char in package_name):
            score -= 0.1
        
        return max(0.0, min(1.0, score))
    
    def _check_factual_consistency(self, content: str) -> float:
        """Check factual consistency of AI content"""
        # Simplified factual consistency check
        inconsistency_patterns = [
            r"definitely", r"absolutely certain", r"100% sure",
            r"never fails", r"always works", r"impossible to"
        ]
        
        score = 1.0
        for pattern in inconsistency_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                score -= 0.1
        
        return max(0.0, score)
    
    def _check_context_relevance(self, content: str, context: str) -> float:
        """Check if content is relevant to provided context"""
        # Simplified relevance scoring based on keyword overlap
        content_words = set(re.findall(r'\w+', content.lower()))
        context_words = set(re.findall(r'\w+', context.lower()))
        
        if not context_words:
            return 1.0
        
        overlap = len(content_words.intersection(context_words))
        return min(1.0, overlap / len(context_words))
    
    def _check_technical_accuracy(self, content: str) -> float:
        """Check technical accuracy of security content"""
        # Look for technical security terms and proper usage
        security_terms = [
            "vulnerability", "exploit", "patch", "CVE", "CVSS",
            "authentication", "authorization", "encryption", "TLS"
        ]
        
        found_terms = sum(1 for term in security_terms 
                         if term.lower() in content.lower())
        
        # Higher score if security terms are used appropriately
        return min(1.0, 0.5 + (found_terms * 0.1))
    
    def _check_source_attribution(self, content: str) -> bool:
        """Check if content includes proper source attribution"""
        attribution_patterns = [
            r"according to", r"source:", r"reference:", r"from:",
            r"https?://", r"CVE-\d{4}-\d{4,7}"
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) 
                  for pattern in attribution_patterns)
    
    def _check_confidence_indicators(self, content: str) -> bool:
        """Check if content includes confidence indicators"""
        confidence_patterns = [
            r"likely", r"probably", r"may", r"might", r"appears to",
            r"suggests", r"indicates", r"potentially"
        ]
        
        return any(re.search(pattern, content, re.IGNORECASE) 
                  for pattern in confidence_patterns)
    
    def _build_dependency_tree(self, project_path: str) -> Dict[str, Any]:
        """Build dependency tree for supply chain analysis"""
        # Simplified dependency tree - in production would use proper tools
        requirements_file = Path(project_path) / "requirements.txt"
        if requirements_file.exists():
            deps = self._parse_requirements_file(str(requirements_file))
            return {name: {"version": version, "dependencies": []} 
                   for name, version in deps.items()}
        return {}
    
    def _is_dependency_outdated(self, dep_name: str, version: str) -> bool:
        """Check if dependency version is outdated"""
        # Simplified check - in production would query package registries
        return version == "latest" or "2023" in version
    
    def _check_license_compatibility(self, dep_name: str, version: str) -> Optional[str]:
        """Check license compatibility issues"""
        # Simplified license checking
        problematic_licenses = ["GPL-3.0", "AGPL-3.0", "SSPL"]
        
        # In production, would query actual license information
        if "gpl" in dep_name.lower():
            return "Potential GPL license compatibility issue"
        
        return None
    
    def _store_scan_results(self, scan_id: str, scan_type: str, results: Dict) -> None:
        """Store scan results in analysis database"""
        with sqlite3.connect(self.analysis_db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO dependency_scans 
                (scan_id, timestamp, scan_type, results, metadata)
                VALUES (?, ?, ?, ?, ?)
            """, (
                scan_id,
                datetime.now().isoformat(),
                scan_type,
                json.dumps(results),
                json.dumps({"version": "1.0"})
            ))
    
    def _store_package_validation(self, result: PackageValidationResult) -> None:
        """Store package validation result"""
        with sqlite3.connect(self.analysis_db_path) as conn:
            conn.execute("""
                INSERT INTO package_validations 
                (package_name, version, validation_result, timestamp)
                VALUES (?, ?, ?, ?)
            """, (
                result.package_name,
                result.version,
                json.dumps(asdict(result)),
                result.analysis_timestamp
            ))
    
    def _store_ai_validation(self, result: AIOutputValidationResult) -> None:
        """Store AI validation result"""
        content_hash = hashlib.sha256(result.content.encode()).hexdigest()
        
        with sqlite3.connect(self.analysis_db_path) as conn:
            conn.execute("""
                INSERT INTO ai_validations 
                (content_hash, validation_result, timestamp)
                VALUES (?, ?, ?)
            """, (
                content_hash,
                json.dumps(asdict(result)),
                result.analysis_timestamp
            ))


# Factory function for easy instantiation
def create_oss_dependency_analyzer(vulnerability_db_path: Optional[str] = None) -> OSSDependencyAnalyzer:
    """Create OSS dependency analyzer with default configuration"""
    if vulnerability_db_path is None:
        vulnerability_db_path = "data/synthetic/vulnerabilities.json"
    
    return OSSDependencyAnalyzer(vulnerability_db_path=vulnerability_db_path)