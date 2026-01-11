"""
OSS-First AI Security Analyst

This module implements the core AI security analysis capabilities using
open-source tools by default, with optional AWS upgrade paths.

OSS Stack:
- Ollama for local LLM analysis
- SQLite for read-only analysis database
- ChromaDB for vector store analysis context
- Local file system for audit trails

AWS Upgrade Options (documented but not implemented by default):
- AWS Bedrock for managed LLM analysis
- AWS DynamoDB for managed database
- AWS OpenSearch for managed vector search
"""

import sqlite3
import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path

from pathlib import Path

import ollama

# Optional import for chromadb (may not be available on all Python versions)
try:
    import chromadb
    from chromadb.config import Settings
    HAS_CHROMADB = True
except ImportError:
    HAS_CHROMADB = False
    chromadb = None
    Settings = None

# Import models for type hints
from .models import SDDArtifacts, SecurityPatternMatch, TextualRecommendation, SeverityLevel


@dataclass
class SecurityAnalysisReport:
    """Report generated from repository security analysis"""
    repo_path: str
    analysis_timestamp: datetime
    repo_structure: Dict[str, Any]
    git_history_summary: Dict[str, Any]
    dependencies: List[Dict[str, Any]]
    security_findings: List[Dict[str, Any]]
    recommendations: List[str]
    confidence_score: float


@dataclass
class ComplianceAnalysisReport:
    """Report generated from SDD compliance analysis"""
    artifacts_found: Dict[str, bool]  # requirements.md, design.md, tasks.md
    compliance_status: str  # "compliant", "partial", "non-compliant"
    violations: List[Dict[str, Any]]
    recommendations: List[str]
    analysis_timestamp: datetime


@dataclass
class SecurityPatternReport:
    """Report generated from security pattern analysis"""
    patterns_detected: List[Dict[str, Any]]
    anti_patterns_detected: List[Dict[str, Any]]
    security_posture_score: float
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    analysis_timestamp: datetime


class OSSSecurityAnalyst:
    """
    OSS-First AI Security Analyst
    
    Provides comprehensive security analysis using local open-source tools.
    Operates in read-only mode for safety and compliance.
    """
    
    def __init__(self, 
                 ollama_endpoint: str = "http://localhost:11434",
                 analysis_db_path: str = "./data/analysis/analysis_context.db",
                 vector_db_path: str = "./data/analysis/vector_db"):
        """
        Initialize the OSS Security Analyst
        
        Args:
            ollama_endpoint: Ollama server endpoint for local LLM analysis
            analysis_db_path: Path to SQLite database for analysis context
            vector_db_path: Path to ChromaDB vector store directory
        """
        self.ollama_endpoint = ollama_endpoint
        self.analysis_db_path = analysis_db_path
        self.vector_db_path = vector_db_path
        
        # Set up logging
        self.logger = logging.getLogger(__name__)
        
        # Initialize Ollama client
        self.ollama_client = ollama.Client(host=ollama_endpoint)
        
        # Initialize analysis database (read-only mode for safety)
        self._init_analysis_database()
        
        # Initialize ChromaDB vector store
        self._init_vector_store()
        
        self.logger.info(f"OSS Security Analyst initialized with Ollama at {ollama_endpoint}")
    
    def _init_analysis_database(self):
        """Initialize SQLite database for analysis context storage"""
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.analysis_db_path), exist_ok=True)
        
        # Create database if it doesn't exist
        if not os.path.exists(self.analysis_db_path):
            conn = sqlite3.connect(self.analysis_db_path)
            cursor = conn.cursor()
            
            # Create tables for analysis context
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS repository_context (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_path TEXT UNIQUE NOT NULL,
                    repo_structure TEXT NOT NULL,
                    git_history TEXT NOT NULL,
                    dependencies TEXT NOT NULL,
                    last_analyzed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    analysis_metadata TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_path TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    file_path TEXT,
                    line_number INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (repo_path) REFERENCES repository_context (repo_path)
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    repo_path TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    report_data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (repo_path) REFERENCES repository_context (repo_path)
                )
            ''')
            
            conn.commit()
            conn.close()
            self.logger.info(f"Created analysis database at {self.analysis_db_path}")
        
        # Open in read-only mode for safety
        self.analysis_db = sqlite3.connect(f"file:{self.analysis_db_path}?mode=ro", uri=True)
        self.analysis_db.row_factory = sqlite3.Row
    
    def _init_vector_store(self):
        """Initialize ChromaDB vector store for analysis context"""
        if not HAS_CHROMADB:
            self.logger.warning("ChromaDB not available - vector store functionality disabled")
            self.chroma_client = None
            self.repo_collection = None
            return
        
        # Ensure directory exists
        os.makedirs(self.vector_db_path, exist_ok=True)
        
        # Initialize ChromaDB client
        self.chroma_client = chromadb.PersistentClient(
            path=self.vector_db_path,
            settings=Settings(
                anonymized_telemetry=False,  # Privacy-first
                allow_reset=False  # Safety measure
            )
        )
        
        # Get or create collection for repository analysis
        self.repo_collection = self.chroma_client.get_or_create_collection(
            name="repository_analysis",
            metadata={"description": "Repository structure and code analysis context"}
        )
        
        self.logger.info(f"Initialized ChromaDB vector store at {self.vector_db_path}")
    
    def analyze_repository(self, repo_path: str) -> SecurityAnalysisReport:
        """
        Analyze repository for security patterns and maintain persistent context
        
        Args:
            repo_path: Path to the repository to analyze
            
        Returns:
            SecurityAnalysisReport with comprehensive analysis results
        """
        self.logger.info(f"Starting repository analysis for {repo_path}")
        
        # Validate repository path
        if not os.path.exists(repo_path):
            raise ValueError(f"Repository path does not exist: {repo_path}")
        
        # Analyze repository structure
        repo_structure = self._analyze_repo_structure(repo_path)
        
        # Analyze git history (if it's a git repository)
        git_history = self._analyze_git_history(repo_path)
        
        # Analyze dependencies
        dependencies = self._analyze_dependencies(repo_path)
        
        # Store context in vector database for future analysis
        self._store_repo_context(repo_path, repo_structure, git_history, dependencies)
        
        # Perform security analysis using Ollama
        security_findings = self._perform_security_analysis(repo_path, repo_structure)
        
        # Generate recommendations
        recommendations = self._generate_security_recommendations(security_findings)
        
        # Calculate confidence score
        confidence_score = self._calculate_confidence_score(security_findings)
        
        # Create analysis report
        report = SecurityAnalysisReport(
            repo_path=repo_path,
            analysis_timestamp=datetime.now(),
            repo_structure=repo_structure,
            git_history_summary=git_history,
            dependencies=dependencies,
            security_findings=security_findings,
            recommendations=recommendations,
            confidence_score=confidence_score
        )
        
        # Store report for future reference
        self._store_analysis_report(repo_path, "security_analysis", report)
        
        self.logger.info(f"Repository analysis completed for {repo_path}")
        return report
    
    def _analyze_repo_structure(self, repo_path: str) -> Dict[str, Any]:
        """Analyze repository structure and file organization"""
        structure = {
            "total_files": 0,
            "file_types": {},
            "directories": [],
            "security_relevant_files": [],
            "config_files": []
        }
        
        repo_path_obj = Path(repo_path)
        
        for file_path in repo_path_obj.rglob("*"):
            if file_path.is_file():
                structure["total_files"] += 1
                
                # Count file types
                suffix = file_path.suffix.lower()
                structure["file_types"][suffix] = structure["file_types"].get(suffix, 0) + 1
                
                # Identify security-relevant files
                if any(keyword in file_path.name.lower() for keyword in 
                       ['security', 'auth', 'credential', 'secret', 'key', 'password']):
                    structure["security_relevant_files"].append(str(file_path.relative_to(repo_path_obj)))
                
                # Identify configuration files
                if suffix in ['.yaml', '.yml', '.json', '.toml', '.ini', '.conf']:
                    structure["config_files"].append(str(file_path.relative_to(repo_path_obj)))
            
            elif file_path.is_dir():
                structure["directories"].append(str(file_path.relative_to(repo_path_obj)))
        
        return structure
    
    def _analyze_git_history(self, repo_path: str) -> Dict[str, Any]:
        """Analyze git history if repository is a git repo"""
        git_history = {
            "is_git_repo": False,
            "total_commits": 0,
            "recent_commits": [],
            "contributors": [],
            "branches": []
        }
        
        git_dir = Path(repo_path) / ".git"
        if git_dir.exists():
            git_history["is_git_repo"] = True
            # Note: In a production system, we would use GitPython or similar
            # For now, we'll mark this as a placeholder for git analysis
            git_history["analysis_note"] = "Git analysis placeholder - would use GitPython in production"
        
        return git_history
    
    def _analyze_dependencies(self, repo_path: str) -> List[Dict[str, Any]]:
        """Analyze project dependencies from various manifest files"""
        dependencies = []
        
        repo_path_obj = Path(repo_path)
        
        # Check for Python dependencies
        requirements_files = ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"]
        for req_file in requirements_files:
            req_path = repo_path_obj / req_file
            if req_path.exists():
                dependencies.append({
                    "type": "python",
                    "file": req_file,
                    "exists": True,
                    "analysis_note": f"Found {req_file} - would parse dependencies in production"
                })
        
        # Check for Node.js dependencies
        package_json = repo_path_obj / "package.json"
        if package_json.exists():
            dependencies.append({
                "type": "nodejs",
                "file": "package.json",
                "exists": True,
                "analysis_note": "Found package.json - would parse dependencies in production"
            })
        
        # Check for Go dependencies
        go_mod = repo_path_obj / "go.mod"
        if go_mod.exists():
            dependencies.append({
                "type": "go",
                "file": "go.mod",
                "exists": True,
                "analysis_note": "Found go.mod - would parse dependencies in production"
            })
        
        return dependencies
    
    def _store_repo_context(self, repo_path: str, repo_structure: Dict[str, Any], 
                           git_history: Dict[str, Any], dependencies: List[Dict[str, Any]]):
        """Store repository context in vector database for persistent analysis"""
        if not HAS_CHROMADB or self.repo_collection is None:
            self.logger.warning("Skipping vector storage - ChromaDB not available")
            return
        
        # Create document for vector storage
        context_doc = {
            "repo_path": repo_path,
            "structure": repo_structure,
            "git_history": git_history,
            "dependencies": dependencies,
            "timestamp": datetime.now().isoformat()
        }
        
        # Convert to text for embedding
        context_text = f"""
        Repository: {repo_path}
        Total Files: {repo_structure.get('total_files', 0)}
        File Types: {', '.join(repo_structure.get('file_types', {}).keys())}
        Security Files: {', '.join(repo_structure.get('security_relevant_files', []))}
        Config Files: {', '.join(repo_structure.get('config_files', []))}
        Dependencies: {len(dependencies)} dependency files found
        Git Repository: {git_history.get('is_git_repo', False)}
        """
        
        # Store in ChromaDB
        self.repo_collection.add(
            documents=[context_text],
            metadatas=[context_doc],
            ids=[f"repo_{hash(repo_path)}_{int(datetime.now().timestamp())}"]
        )
        
        self.logger.info(f"Stored repository context for {repo_path} in vector database")
    
    def _perform_security_analysis(self, repo_path: str, repo_structure: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Perform security analysis using Ollama LLM"""
        security_findings = []
        
        try:
            # Prepare analysis prompt
            analysis_prompt = f"""
            Analyze the following repository structure for security concerns:
            
            Repository: {repo_path}
            Total Files: {repo_structure.get('total_files', 0)}
            File Types: {repo_structure.get('file_types', {})}
            Security-relevant Files: {repo_structure.get('security_relevant_files', [])}
            Configuration Files: {repo_structure.get('config_files', [])}
            
            Please identify potential security issues and provide recommendations.
            Focus on:
            1. Exposed credentials or secrets
            2. Insecure configurations
            3. Missing security files (.gitignore, security policies)
            4. Suspicious file patterns
            
            Respond in JSON format with findings array.
            """
            
            # Query Ollama (with error handling for when Ollama is not available)
            try:
                response = self.ollama_client.generate(
                    model="llama2",  # Default model, could be configurable
                    prompt=analysis_prompt
                )
                
                # Parse response (simplified for now)
                security_findings.append({
                    "type": "llm_analysis",
                    "severity": "info",
                    "description": "LLM-based security analysis completed",
                    "details": response.get("response", "No response"),
                    "confidence": 0.7
                })
                
            except Exception as ollama_error:
                self.logger.warning(f"Ollama analysis failed: {ollama_error}")
                security_findings.append({
                    "type": "analysis_error",
                    "severity": "warning",
                    "description": "LLM analysis unavailable - Ollama service not accessible",
                    "details": str(ollama_error),
                    "confidence": 0.0
                })
        
        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            security_findings.append({
                "type": "analysis_error",
                "severity": "error",
                "description": "Security analysis failed",
                "details": str(e),
                "confidence": 0.0
            })
        
        # Add basic structural security checks
        if not repo_structure.get('security_relevant_files'):
            security_findings.append({
                "type": "missing_security_files",
                "severity": "medium",
                "description": "No security-related files detected",
                "recommendation": "Consider adding security documentation and policies",
                "confidence": 0.9
            })
        
        return security_findings
    
    def _generate_security_recommendations(self, security_findings: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable security recommendations based on findings"""
        recommendations = []
        
        for finding in security_findings:
            if finding.get("recommendation"):
                recommendations.append(finding["recommendation"])
        
        # Add general recommendations
        recommendations.extend([
            "Implement automated security scanning in CI/CD pipeline",
            "Regular dependency vulnerability assessments",
            "Establish security code review processes",
            "Implement secrets management best practices"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _calculate_confidence_score(self, security_findings: List[Dict[str, Any]]) -> float:
        """Calculate confidence score for the analysis"""
        if not security_findings:
            return 0.0
        
        total_confidence = sum(finding.get("confidence", 0.0) for finding in security_findings)
        return total_confidence / len(security_findings)
    
    def validate_sdd_compliance(self, artifacts: 'SDDArtifacts') -> ComplianceAnalysisReport:
        """
        Validate Spec-Driven Development compliance using local rule engine
        
        Args:
            artifacts: SDD artifacts to validate (requirements.md, design.md, tasks.md)
            
        Returns:
            ComplianceAnalysisReport with compliance status and recommendations
        """
        self.logger.info("Starting SDD compliance validation")
        
        violations = []
        compliance_status = "compliant"
        recommendations = []
        
        # Check for required SDD artifacts
        required_artifacts = {
            "requirements.md": artifacts.requirements_exists,
            "design.md": artifacts.design_exists,
            "tasks.md": artifacts.tasks_exists
        }
        
        missing_artifacts = [name for name, exists in required_artifacts.items() if not exists]
        
        if missing_artifacts:
            compliance_status = "non_compliant"
            violations.append({
                "rule_id": "SDD-001",
                "rule_name": "Required SDD Artifacts",
                "severity": "high",
                "description": f"Missing required SDD artifacts: {', '.join(missing_artifacts)}",
                "expected": "All three SDD artifacts must be present",
                "actual": f"Missing: {', '.join(missing_artifacts)}",
                "remediation_steps": [
                    f"Create missing {artifact}" for artifact in missing_artifacts
                ]
            })
            recommendations.extend([
                f"Create {artifact} following SDD methodology" for artifact in missing_artifacts
            ])
        
        # Validate artifact content if available
        if artifacts.requirements_md:
            req_violations = self._validate_requirements_content(artifacts.requirements_md)
            violations.extend(req_violations)
            if req_violations and compliance_status == "compliant":
                compliance_status = "partial"
        
        if artifacts.design_md:
            design_violations = self._validate_design_content(artifacts.design_md)
            violations.extend(design_violations)
            if design_violations and compliance_status == "compliant":
                compliance_status = "partial"
        
        if artifacts.tasks_md:
            tasks_violations = self._validate_tasks_content(artifacts.tasks_md)
            violations.extend(tasks_violations)
            if tasks_violations and compliance_status == "compliant":
                compliance_status = "partial"
        
        # Generate general recommendations
        if compliance_status == "compliant":
            recommendations.append("SDD compliance maintained - continue following methodology")
        else:
            recommendations.extend([
                "Review SDD methodology documentation",
                "Ensure all artifacts are kept in sync",
                "Implement automated SDD compliance checking"
            ])
        
        report = ComplianceAnalysisReport(
            artifacts_found=required_artifacts,
            compliance_status=compliance_status,
            violations=violations,
            recommendations=recommendations,
            analysis_timestamp=datetime.now()
        )
        
        # Store compliance report
        self._store_analysis_report(artifacts.requirements_md or "unknown", "sdd_compliance", report)
        
        self.logger.info(f"SDD compliance validation completed: {compliance_status}")
        return report
    
    def _validate_requirements_content(self, requirements_content: str) -> List[Dict[str, Any]]:
        """Validate requirements.md content structure"""
        violations = []
        
        # Check for required sections
        required_sections = [
            "# Requirements Document",
            "## Introduction", 
            "## Glossary",
            "## Requirements"
        ]
        
        for section in required_sections:
            if section not in requirements_content:
                violations.append({
                    "rule_id": "SDD-REQ-001",
                    "rule_name": "Required Requirements Sections",
                    "severity": "medium",
                    "description": f"Missing required section: {section}",
                    "expected": f"Section '{section}' should be present",
                    "actual": "Section not found",
                    "remediation_steps": [f"Add {section} section to requirements.md"]
                })
        
        # Check for EARS patterns in acceptance criteria
        if "WHEN" not in requirements_content and "THE" not in requirements_content and "SHALL" not in requirements_content:
            violations.append({
                "rule_id": "SDD-REQ-002", 
                "rule_name": "EARS Pattern Usage",
                "severity": "medium",
                "description": "Requirements should use EARS patterns (WHEN/THE/SHALL)",
                "expected": "Acceptance criteria using EARS patterns",
                "actual": "No EARS patterns detected",
                "remediation_steps": ["Rewrite acceptance criteria using EARS patterns"]
            })
        
        return violations
    
    def _validate_design_content(self, design_content: str) -> List[Dict[str, Any]]:
        """Validate design.md content structure"""
        violations = []
        
        # Check for required sections
        required_sections = [
            "# Design Document",
            "## Overview",
            "## Architecture", 
            "## Components and Interfaces",
            "## Data Models",
            "## Correctness Properties"
        ]
        
        for section in required_sections:
            if section not in design_content:
                violations.append({
                    "rule_id": "SDD-DES-001",
                    "rule_name": "Required Design Sections",
                    "severity": "medium", 
                    "description": f"Missing required section: {section}",
                    "expected": f"Section '{section}' should be present",
                    "actual": "Section not found",
                    "remediation_steps": [f"Add {section} section to design.md"]
                })
        
        # Check for correctness properties
        if "Property" not in design_content or "**Validates: Requirements" not in design_content:
            violations.append({
                "rule_id": "SDD-DES-002",
                "rule_name": "Correctness Properties",
                "severity": "high",
                "description": "Design should include correctness properties with requirement traceability",
                "expected": "Properties with **Validates: Requirements X.Y** annotations",
                "actual": "No correctness properties found",
                "remediation_steps": ["Add correctness properties section with requirement traceability"]
            })
        
        return violations
    
    def _validate_tasks_content(self, tasks_content: str) -> List[Dict[str, Any]]:
        """Validate tasks.md content structure"""
        violations = []
        
        # Check for required sections
        required_sections = [
            "# Implementation Plan",
            "## Overview",
            "## Tasks"
        ]
        
        for section in required_sections:
            if section not in tasks_content:
                violations.append({
                    "rule_id": "SDD-TSK-001",
                    "rule_name": "Required Task Sections",
                    "severity": "medium",
                    "description": f"Missing required section: {section}",
                    "expected": f"Section '{section}' should be present", 
                    "actual": "Section not found",
                    "remediation_steps": [f"Add {section} section to tasks.md"]
                })
        
        # Check for requirement traceability
        if "_Requirements:" not in tasks_content:
            violations.append({
                "rule_id": "SDD-TSK-002",
                "rule_name": "Requirement Traceability",
                "severity": "medium",
                "description": "Tasks should include requirement traceability",
                "expected": "Tasks with _Requirements: X.Y_ annotations",
                "actual": "No requirement traceability found",
                "remediation_steps": ["Add requirement references to all tasks"]
            })
        
        return violations
    
    def analyze_steering_files_compliance(self, steering_files_path: str) -> Dict[str, Any]:
        """
        Analyze compliance against Steering Files policies
        
        Args:
            steering_files_path: Path to steering files directory
            
        Returns:
            Dictionary with steering file compliance analysis
        """
        self.logger.info(f"Analyzing steering files compliance at {steering_files_path}")
        
        compliance_report = {
            "steering_files_found": [],
            "policies_analyzed": [],
            "violations": [],
            "recommendations": [],
            "compliance_score": 1.0
        }
        
        steering_path = Path(steering_files_path)
        
        if not steering_path.exists():
            compliance_report["violations"].append({
                "rule_id": "STEERING-001",
                "severity": "medium",
                "description": "Steering files directory not found",
                "recommendation": f"Create steering files directory at {steering_files_path}"
            })
            compliance_report["compliance_score"] = 0.5
            return compliance_report
        
        # Find all steering files
        steering_files = list(steering_path.glob("*.md"))
        compliance_report["steering_files_found"] = [str(f.relative_to(steering_path)) for f in steering_files]
        
        # Analyze each steering file
        for steering_file in steering_files:
            try:
                content = steering_file.read_text(encoding='utf-8')
                policy_analysis = self._analyze_steering_file_content(steering_file.name, content)
                compliance_report["policies_analyzed"].append(policy_analysis)
                
                # Check for policy violations
                if policy_analysis.get("violations"):
                    compliance_report["violations"].extend(policy_analysis["violations"])
                    compliance_report["compliance_score"] *= 0.8  # Reduce score for violations
                
            except Exception as e:
                self.logger.warning(f"Failed to analyze steering file {steering_file}: {e}")
                compliance_report["violations"].append({
                    "rule_id": "STEERING-002",
                    "severity": "low",
                    "description": f"Could not analyze steering file {steering_file.name}",
                    "details": str(e)
                })
        
        # Generate recommendations
        if not steering_files:
            compliance_report["recommendations"].append("Create steering files to define project policies")
        else:
            compliance_report["recommendations"].append("Steering files found - ensure they are kept up to date")
        
        if compliance_report["violations"]:
            compliance_report["recommendations"].append("Address steering file policy violations")
        
        self.logger.info(f"Steering files compliance analysis completed: {compliance_report['compliance_score']:.2f}")
        return compliance_report
    
    def _analyze_steering_file_content(self, filename: str, content: str) -> Dict[str, Any]:
        """Analyze individual steering file content"""
        analysis = {
            "filename": filename,
            "policies_found": [],
            "violations": [],
            "recommendations": []
        }
        
        # Check for basic structure
        if not content.strip():
            analysis["violations"].append({
                "rule_id": "STEERING-003",
                "severity": "medium",
                "description": f"Steering file {filename} is empty",
                "recommendation": f"Add content to {filename} or remove if not needed"
            })
        
        # Look for policy definitions (basic heuristics)
        lines = content.split('\n')
        policy_indicators = ['policy', 'rule', 'standard', 'guideline', 'requirement']
        
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if any(indicator in line_lower for indicator in policy_indicators):
                analysis["policies_found"].append({
                    "line": i + 1,
                    "content": line.strip(),
                    "type": "policy_definition"
                })
        
        if not analysis["policies_found"]:
            analysis["recommendations"].append(f"Consider adding explicit policy definitions to {filename}")
        
        return analysis
    
    def analyze_security_patterns(self, codebase_path: str) -> SecurityPatternReport:
        """
        Analyze codebase for security patterns and anti-patterns
        
        Args:
            codebase_path: Path to the codebase to analyze
            
        Returns:
            SecurityPatternReport with detected patterns and recommendations
        """
        self.logger.info(f"Starting security pattern analysis for {codebase_path}")
        
        patterns_detected = []
        anti_patterns_detected = []
        
        # Analyze codebase structure and files
        codebase_path_obj = Path(codebase_path)
        
        if not codebase_path_obj.exists():
            raise ValueError(f"Codebase path does not exist: {codebase_path}")
        
        # Scan for security patterns and anti-patterns
        for file_path in codebase_path_obj.rglob("*"):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts', '.java', '.go', '.cpp', '.c']:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    
                    # Analyze file for security patterns
                    file_patterns = self._analyze_file_security_patterns(str(file_path), content)
                    patterns_detected.extend(file_patterns['patterns'])
                    anti_patterns_detected.extend(file_patterns['anti_patterns'])
                    
                except Exception as e:
                    self.logger.warning(f"Failed to analyze file {file_path}: {e}")
        
        # Calculate security posture score
        security_posture_score = self._calculate_security_posture_score(patterns_detected, anti_patterns_detected)
        
        # Generate risk assessment
        risk_assessment = self._generate_risk_assessment(patterns_detected, anti_patterns_detected)
        
        # Generate security recommendations
        recommendations = self._generate_security_pattern_recommendations(patterns_detected, anti_patterns_detected)
        
        report = SecurityPatternReport(
            patterns_detected=patterns_detected,
            anti_patterns_detected=anti_patterns_detected,
            security_posture_score=security_posture_score,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
            analysis_timestamp=datetime.now()
        )
        
        # Store security pattern report
        self._store_analysis_report(codebase_path, "security_patterns", report)
        
        self.logger.info(f"Security pattern analysis completed for {codebase_path}")
        return report
    
    def _analyze_file_security_patterns(self, file_path: str, content: str) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze a single file for security patterns and anti-patterns"""
        patterns = []
        anti_patterns = []
        
        lines = content.split('\n')
        
        # Security patterns to detect
        security_patterns = {
            'input_validation': [
                r'validate\w*\(',
                r'sanitize\w*\(',
                r'escape\w*\(',
                r'filter\w*\('
            ],
            'authentication': [
                r'authenticate\w*\(',
                r'login\w*\(',
                r'verify\w*\(',
                r'check_auth\w*\('
            ],
            'authorization': [
                r'authorize\w*\(',
                r'check_permission\w*\(',
                r'has_role\w*\(',
                r'require_auth\w*\('
            ],
            'encryption': [
                r'encrypt\w*\(',
                r'decrypt\w*\(',
                r'hash\w*\(',
                r'bcrypt\w*\(',
                r'scrypt\w*\(',
                r'pbkdf2\w*\('
            ],
            'secure_random': [
                r'secrets\.',
                r'random\.SystemRandom',
                r'crypto\.randomBytes',
                r'SecureRandom'
            ]
        }
        
        # Anti-patterns to detect
        security_anti_patterns = {
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']'
            ],
            'sql_injection_risk': [
                r'execute\s*\(\s*["\'].*%.*["\']',
                r'query\s*\(\s*["\'].*\+.*["\']',
                r'SELECT.*\+.*FROM',
                r'INSERT.*\+.*VALUES'
            ],
            'weak_crypto': [
                r'md5\(',
                r'sha1\(',
                r'DES\(',
                r'RC4\('
            ],
            'insecure_random': [
                r'random\.random\(',
                r'Math\.random\(',
                r'rand\(\)',
                r'srand\('
            ],
            'debug_info_leak': [
                r'print\s*\(.*password',
                r'console\.log\s*\(.*secret',
                r'debug\s*=\s*True',
                r'DEBUG\s*=\s*True'
            ]
        }
        
        # Scan for patterns
        for line_num, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            # Check for security patterns (good practices)
            for pattern_type, pattern_regexes in security_patterns.items():
                for pattern_regex in pattern_regexes:
                    import re
                    if re.search(pattern_regex, line, re.IGNORECASE):
                        patterns.append({
                            'pattern_id': f'SEC_PATTERN_{pattern_type.upper()}',
                            'pattern_name': f'Security Pattern: {pattern_type.replace("_", " ").title()}',
                            'pattern_type': 'security_pattern',
                            'description': f'Good security practice detected: {pattern_type.replace("_", " ")}',
                            'file_path': file_path,
                            'line_range': (line_num, line_num),
                            'confidence': 0.8,
                            'impact_assessment': 'Positive security impact',
                            'remediation_suggestion': None
                        })
            
            # Check for anti-patterns (security issues)
            for anti_pattern_type, pattern_regexes in security_anti_patterns.items():
                for pattern_regex in pattern_regexes:
                    if re.search(pattern_regex, line, re.IGNORECASE):
                        anti_patterns.append({
                            'pattern_id': f'SEC_ANTI_PATTERN_{anti_pattern_type.upper()}',
                            'pattern_name': f'Security Anti-Pattern: {anti_pattern_type.replace("_", " ").title()}',
                            'pattern_type': 'anti_pattern',
                            'description': f'Security risk detected: {anti_pattern_type.replace("_", " ")}',
                            'file_path': file_path,
                            'line_range': (line_num, line_num),
                            'confidence': 0.9,
                            'impact_assessment': 'High security risk',
                            'remediation_suggestion': self._get_remediation_suggestion(anti_pattern_type)
                        })
        
        return {
            'patterns': patterns,
            'anti_patterns': anti_patterns
        }
    
    def _get_remediation_suggestion(self, anti_pattern_type: str) -> str:
        """Get remediation suggestion for a specific anti-pattern"""
        suggestions = {
            'hardcoded_secrets': 'Use environment variables or secure secret management systems',
            'sql_injection_risk': 'Use parameterized queries or prepared statements',
            'weak_crypto': 'Use strong cryptographic algorithms like SHA-256, AES, or bcrypt',
            'insecure_random': 'Use cryptographically secure random number generators',
            'debug_info_leak': 'Remove debug statements and sensitive information from logs'
        }
        
        return suggestions.get(anti_pattern_type, 'Review and fix security issue')
    
    def _calculate_security_posture_score(self, patterns: List[Dict[str, Any]], 
                                        anti_patterns: List[Dict[str, Any]]) -> float:
        """Calculate overall security posture score"""
        if not patterns and not anti_patterns:
            return 0.5  # Neutral score when no patterns detected
        
        # Positive score for security patterns
        pattern_score = len(patterns) * 0.1
        
        # Negative score for anti-patterns
        anti_pattern_penalty = len(anti_patterns) * 0.2
        
        # Base score starts at 0.5
        score = 0.5 + pattern_score - anti_pattern_penalty
        
        # Clamp between 0.0 and 1.0
        return max(0.0, min(1.0, score))
    
    def _generate_risk_assessment(self, patterns: List[Dict[str, Any]], 
                                anti_patterns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate risk assessment based on detected patterns"""
        risk_assessment = {
            'overall_risk_level': 'low',
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'positive_patterns': len(patterns),
            'risk_factors': []
        }
        
        # Count issues by severity
        for anti_pattern in anti_patterns:
            if 'hardcoded_secrets' in anti_pattern['pattern_id'].lower():
                risk_assessment['critical_issues'] += 1
                risk_assessment['risk_factors'].append('Hardcoded secrets detected')
            elif 'sql_injection' in anti_pattern['pattern_id'].lower():
                risk_assessment['high_issues'] += 1
                risk_assessment['risk_factors'].append('SQL injection risk detected')
            elif 'weak_crypto' in anti_pattern['pattern_id'].lower():
                risk_assessment['high_issues'] += 1
                risk_assessment['risk_factors'].append('Weak cryptography detected')
            else:
                risk_assessment['medium_issues'] += 1
        
        # Determine overall risk level
        if risk_assessment['critical_issues'] > 0:
            risk_assessment['overall_risk_level'] = 'critical'
        elif risk_assessment['high_issues'] > 0:
            risk_assessment['overall_risk_level'] = 'high'
        elif risk_assessment['medium_issues'] > 2:
            risk_assessment['overall_risk_level'] = 'medium'
        elif risk_assessment['medium_issues'] > 0 or len(patterns) == 0:
            risk_assessment['overall_risk_level'] = 'low'
        
        return risk_assessment
    
    def _generate_security_pattern_recommendations(self, patterns: List[Dict[str, Any]], 
                                                 anti_patterns: List[Dict[str, Any]]) -> List[str]:
        """Generate security recommendations based on pattern analysis"""
        recommendations = []
        
        # Recommendations based on anti-patterns found
        anti_pattern_types = set()
        for anti_pattern in anti_patterns:
            if 'hardcoded_secrets' in anti_pattern['pattern_id'].lower():
                anti_pattern_types.add('secrets_management')
            elif 'sql_injection' in anti_pattern['pattern_id'].lower():
                anti_pattern_types.add('input_validation')
            elif 'weak_crypto' in anti_pattern['pattern_id'].lower():
                anti_pattern_types.add('cryptography')
            elif 'insecure_random' in anti_pattern['pattern_id'].lower():
                anti_pattern_types.add('random_generation')
            elif 'debug_info' in anti_pattern['pattern_id'].lower():
                anti_pattern_types.add('information_disclosure')
        
        # Generate specific recommendations
        if 'secrets_management' in anti_pattern_types:
            recommendations.append('Implement secure secrets management using environment variables or dedicated secret stores')
        
        if 'input_validation' in anti_pattern_types:
            recommendations.append('Implement comprehensive input validation and use parameterized queries')
        
        if 'cryptography' in anti_pattern_types:
            recommendations.append('Upgrade to strong cryptographic algorithms and review all crypto usage')
        
        if 'random_generation' in anti_pattern_types:
            recommendations.append('Use cryptographically secure random number generators for security-sensitive operations')
        
        if 'information_disclosure' in anti_pattern_types:
            recommendations.append('Remove debug information and implement proper logging practices')
        
        # General recommendations
        if anti_patterns:
            recommendations.append('Conduct regular security code reviews')
            recommendations.append('Implement automated security scanning in CI/CD pipeline')
        
        if patterns:
            recommendations.append('Continue following detected security best practices')
        else:
            recommendations.append('Implement security patterns for authentication, authorization, and input validation')
        
        # Always include these general recommendations
        recommendations.extend([
            'Regular security training for development team',
            'Implement security testing as part of development process',
            'Consider third-party security audit for critical components'
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def generate_fix_recommendations(self, violations: List[Dict[str, Any]]) -> List[TextualRecommendation]:
        """
        Generate textual fix recommendations for detected violations
        
        Args:
            violations: List of security violations or compliance issues
            
        Returns:
            List of TextualRecommendation objects with actionable guidance
        """
        self.logger.info(f"Generating fix recommendations for {len(violations)} violations")
        
        recommendations = []
        
        for i, violation in enumerate(violations):
            # Determine priority based on severity
            severity_map = {
                'critical': SeverityLevel.CRITICAL,
                'high': SeverityLevel.HIGH,
                'medium': SeverityLevel.MEDIUM,
                'low': SeverityLevel.LOW
            }
            
            priority = severity_map.get(violation.get('severity', 'medium'), SeverityLevel.MEDIUM)
            
            # Generate recommendation based on violation type
            if 'hardcoded_secrets' in violation.get('description', '').lower():
                recommendation = TextualRecommendation(
                    id=f"REC-{i+1:03d}",
                    title="Remove Hardcoded Secrets",
                    description="Hardcoded secrets pose a critical security risk and should be externalized",
                    priority=SeverityLevel.CRITICAL,
                    category="security",
                    implementation_steps=[
                        "Move secrets to environment variables",
                        "Use a secure secret management system (e.g., HashiCorp Vault, AWS Secrets Manager)",
                        "Implement secret rotation policies",
                        "Audit code for other hardcoded credentials"
                    ],
                    estimated_effort="medium",
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
                    ],
                    applies_to_files=[violation.get('file_path', '')]
                )
            
            elif 'sql_injection' in violation.get('description', '').lower():
                recommendation = TextualRecommendation(
                    id=f"REC-{i+1:03d}",
                    title="Fix SQL Injection Vulnerability",
                    description="SQL injection vulnerabilities allow attackers to manipulate database queries",
                    priority=SeverityLevel.HIGH,
                    category="security",
                    implementation_steps=[
                        "Replace string concatenation with parameterized queries",
                        "Use prepared statements or ORM query builders",
                        "Implement input validation and sanitization",
                        "Apply principle of least privilege to database accounts"
                    ],
                    estimated_effort="medium",
                    references=[
                        "https://owasp.org/www-project-top-ten/2017/A1_2017-Injection",
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                    ],
                    applies_to_files=[violation.get('file_path', '')]
                )
            
            elif 'sdd' in violation.get('rule_id', '').lower():
                recommendation = TextualRecommendation(
                    id=f"REC-{i+1:03d}",
                    title="Fix SDD Compliance Issue",
                    description=violation.get('description', 'SDD compliance violation detected'),
                    priority=priority,
                    category="compliance",
                    implementation_steps=violation.get('remediation_steps', [
                        "Review SDD methodology requirements",
                        "Update documentation to meet standards",
                        "Ensure proper requirement traceability"
                    ]),
                    estimated_effort="low",
                    references=[
                        "https://spec-driven-development.com/",
                        "Internal SDD methodology documentation"
                    ],
                    applies_to_files=[]
                )
            
            else:
                # Generic recommendation
                recommendation = TextualRecommendation(
                    id=f"REC-{i+1:03d}",
                    title=f"Address {violation.get('rule_name', 'Security Issue')}",
                    description=violation.get('description', 'Security or compliance issue detected'),
                    priority=priority,
                    category="security",
                    implementation_steps=violation.get('remediation_steps', [
                        "Review the identified issue",
                        "Implement appropriate security controls",
                        "Test the fix thoroughly",
                        "Update documentation as needed"
                    ]),
                    estimated_effort="medium",
                    references=[],
                    applies_to_files=[violation.get('file_path', '')]
                )
            
            recommendations.append(recommendation)
        
        self.logger.info(f"Generated {len(recommendations)} fix recommendations")
        return recommendations
    
    def _store_analysis_report(self, repo_path: str, report_type: str, report: Any):
        """Store analysis report in database for future reference"""
        # Note: In read-only mode, we can't actually store to the database
        # This would be implemented when we have write access
        self.logger.info(f"Analysis report generated for {repo_path} (read-only mode - not persisted)")