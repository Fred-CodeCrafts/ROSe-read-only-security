"""
Documentation and Setup Analysis

Provides comprehensive analysis of documentation completeness, setup procedures,
and deployment readiness with security and operational assessments.
"""

import os
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import re


@dataclass
class DocumentationGap:
    """Represents a gap in documentation"""
    gap_id: str
    gap_type: str  # 'missing_file', 'incomplete_section', 'outdated_content', 'broken_link'
    severity: str  # 'critical', 'high', 'medium', 'low'
    description: str
    file_path: Optional[str] = None
    section: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)


@dataclass
class SetupValidationResult:
    """Result of setup procedure validation"""
    procedure_name: str
    status: str  # 'valid', 'invalid', 'partial', 'untested'
    steps_validated: int
    total_steps: int
    issues_found: List[str] = field(default_factory=list)
    execution_time_seconds: float = 0.0


@dataclass
class DeploymentReadinessAssessment:
    """Assessment of deployment readiness"""
    overall_readiness: str  # 'ready', 'needs_work', 'not_ready'
    readiness_score: float  # 0.0 to 1.0
    security_assessment: Dict[str, Any] = field(default_factory=dict)
    operational_assessment: Dict[str, Any] = field(default_factory=dict)
    missing_requirements: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class DocumentationAnalysisReport:
    """Comprehensive documentation analysis report"""
    analysis_id: str
    timestamp: datetime
    target_path: str
    documentation_gaps: List[DocumentationGap]
    setup_validation_results: List[SetupValidationResult]
    deployment_readiness: DeploymentReadinessAssessment
    governance_compliance: Dict[str, Any]
    quality_score: float  # 0.0 to 1.0
    summary: str


class DocumentationAnalyzer:
    """
    Documentation and Setup Analysis Engine
    
    Analyzes documentation completeness, validates setup procedures,
    and assesses deployment readiness with security considerations.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Documentation requirements
        self.required_docs = {
            'README.md': {'critical': True, 'sections': ['Installation', 'Usage', 'Configuration']},
            'SECURITY.md': {'critical': True, 'sections': ['Reporting', 'Policy']},
            'CONTRIBUTING.md': {'critical': False, 'sections': ['Guidelines', 'Process']},
            'LICENSE': {'critical': True, 'sections': []},
            'CHANGELOG.md': {'critical': False, 'sections': []},
            'docs/setup/README.md': {'critical': True, 'sections': ['Prerequisites', 'Installation']},
            'requirements.txt': {'critical': True, 'sections': []},
            'docker-compose.yml': {'critical': False, 'sections': []}
        }
        
        # Setup script patterns
        self.setup_script_patterns = [
            r'setup\.py$',
            r'setup\.sh$',
            r'setup\.ps1$',
            r'install\.sh$',
            r'install\.ps1$',
            r'Makefile$',
            r'package\.json$'
        ]
        
        # Security-related file patterns
        self.security_file_patterns = [
            r'\.env\.example$',
            r'\.gitignore$',
            r'\.gitleaks\.toml$',
            r'security\.md$',
            r'SECURITY\.md$'
        ]
    
    def analyze_documentation_completeness(self, target_path: str) -> DocumentationAnalysisReport:
        """
        Perform comprehensive documentation analysis
        
        Args:
            target_path: Path to analyze
            
        Returns:
            DocumentationAnalysisReport with complete analysis
        """
        self.logger.info(f"Starting documentation analysis for {target_path}")
        
        analysis_id = f"doc_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        target_path_obj = Path(target_path)
        
        # Analyze documentation gaps
        documentation_gaps = self._analyze_documentation_gaps(target_path_obj)
        
        # Validate setup procedures
        setup_validation_results = self._validate_setup_procedures(target_path_obj)
        
        # Assess deployment readiness
        deployment_readiness = self._assess_deployment_readiness(target_path_obj)
        
        # Check governance compliance
        governance_compliance = self._check_governance_compliance(target_path_obj)
        
        # Calculate quality score
        quality_score = self._calculate_documentation_quality_score(
            documentation_gaps, setup_validation_results, deployment_readiness
        )
        
        # Generate summary
        summary = self._generate_analysis_summary(
            documentation_gaps, setup_validation_results, deployment_readiness, quality_score
        )
        
        report = DocumentationAnalysisReport(
            analysis_id=analysis_id,
            timestamp=datetime.now(),
            target_path=target_path,
            documentation_gaps=documentation_gaps,
            setup_validation_results=setup_validation_results,
            deployment_readiness=deployment_readiness,
            governance_compliance=governance_compliance,
            quality_score=quality_score,
            summary=summary
        )
        
        self.logger.info(f"Documentation analysis completed: {quality_score:.2f} quality score")
        return report
    
    def _analyze_documentation_gaps(self, target_path: Path) -> List[DocumentationGap]:
        """Analyze documentation gaps and missing files"""
        gaps = []
        
        for doc_file, requirements in self.required_docs.items():
            file_path = target_path / doc_file
            
            if not file_path.exists():
                # Missing file
                severity = 'critical' if requirements['critical'] else 'medium'
                gaps.append(DocumentationGap(
                    gap_id=f"missing_{doc_file.replace('/', '_').replace('.', '_')}",
                    gap_type='missing_file',
                    severity=severity,
                    description=f"Required documentation file missing: {doc_file}",
                    file_path=str(file_path),
                    recommendations=[f"Create {doc_file} with appropriate content"]
                ))
            else:
                # Check file content
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    file_gaps = self._analyze_file_content(doc_file, content, requirements)
                    gaps.extend(file_gaps)
                except Exception as e:
                    gaps.append(DocumentationGap(
                        gap_id=f"unreadable_{doc_file.replace('/', '_').replace('.', '_')}",
                        gap_type='unreadable_file',
                        severity='medium',
                        description=f"Cannot read documentation file: {doc_file} - {e}",
                        file_path=str(file_path),
                        recommendations=[f"Fix file encoding or permissions for {doc_file}"]
                    ))
        
        # Check for additional documentation quality issues
        gaps.extend(self._check_documentation_quality(target_path))
        
        return gaps
    
    def _analyze_file_content(self, file_name: str, content: str, requirements: Dict[str, Any]) -> List[DocumentationGap]:
        """Analyze individual file content for gaps"""
        gaps = []
        
        # Check for required sections
        for section in requirements.get('sections', []):
            if not self._has_section(content, section):
                gaps.append(DocumentationGap(
                    gap_id=f"missing_section_{file_name.replace('/', '_').replace('.', '_')}_{section.lower()}",
                    gap_type='incomplete_section',
                    severity='medium',
                    description=f"Missing required section '{section}' in {file_name}",
                    file_path=file_name,
                    section=section,
                    recommendations=[f"Add '{section}' section to {file_name}"]
                ))
        
        # Check for minimum content length
        if len(content.strip()) < 100:
            gaps.append(DocumentationGap(
                gap_id=f"minimal_content_{file_name.replace('/', '_').replace('.', '_')}",
                gap_type='incomplete_content',
                severity='low',
                description=f"Documentation file {file_name} has minimal content",
                file_path=file_name,
                recommendations=[f"Expand content in {file_name} with more detailed information"]
            ))
        
        # Check for broken links (basic check)
        broken_links = self._find_broken_links(content)
        for link in broken_links:
            gaps.append(DocumentationGap(
                gap_id=f"broken_link_{hash(link)}",
                gap_type='broken_link',
                severity='low',
                description=f"Potentially broken link in {file_name}: {link}",
                file_path=file_name,
                recommendations=[f"Verify and fix link: {link}"]
            ))
        
        return gaps
    
    def _has_section(self, content: str, section: str) -> bool:
        """Check if content has a specific section"""
        # Look for markdown headers or section indicators
        patterns = [
            rf'^#{1,6}\s+.*{re.escape(section)}.*$',  # Markdown headers
            rf'^{re.escape(section)}:?$',  # Simple section headers
            rf'## {re.escape(section)}',  # Specific markdown format
        ]
        
        for pattern in patterns:
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                return True
        
        return False
    
    def _find_broken_links(self, content: str) -> List[str]:
        """Find potentially broken links in content"""
        # Simple regex for markdown links and URLs
        link_patterns = [
            r'\[([^\]]+)\]\(([^)]+)\)',  # Markdown links
            r'https?://[^\s<>"]+',  # HTTP URLs
        ]
        
        broken_links = []
        for pattern in link_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    url = match[1]  # Markdown link URL
                else:
                    url = match  # Direct URL
                
                # Basic checks for obviously broken links
                if url.startswith('http') and ('localhost' in url or '127.0.0.1' in url):
                    broken_links.append(url)
                elif url.startswith('./') or url.startswith('../'):
                    # Relative links - would need file system check
                    pass
        
        return broken_links
    
    def _check_documentation_quality(self, target_path: Path) -> List[DocumentationGap]:
        """Check overall documentation quality"""
        gaps = []
        
        # Check for documentation directory structure
        docs_dir = target_path / 'docs'
        if not docs_dir.exists():
            gaps.append(DocumentationGap(
                gap_id="missing_docs_directory",
                gap_type='missing_structure',
                severity='medium',
                description="No dedicated documentation directory found",
                recommendations=["Create 'docs' directory for organized documentation"]
            ))
        
        # Check for API documentation
        api_doc_patterns = ['api.md', 'docs/api.md', 'API.md', 'docs/API.md']
        has_api_docs = any((target_path / pattern).exists() for pattern in api_doc_patterns)
        
        if not has_api_docs:
            # Check if this looks like a project that should have API docs
            has_api_files = any(
                file_path.suffix in ['.py', '.js', '.ts', '.go', '.java']
                for file_path in target_path.rglob('*')
                if file_path.is_file()
            )
            
            if has_api_files:
                gaps.append(DocumentationGap(
                    gap_id="missing_api_documentation",
                    gap_type='missing_file',
                    severity='low',
                    description="No API documentation found for code project",
                    recommendations=["Consider adding API documentation"]
                ))
        
        return gaps
    
    def _validate_setup_procedures(self, target_path: Path) -> List[SetupValidationResult]:
        """Validate setup procedures and scripts"""
        results = []
        
        # Find setup scripts
        setup_scripts = []
        for pattern in self.setup_script_patterns:
            setup_scripts.extend(target_path.glob(pattern))
            setup_scripts.extend(target_path.glob(f"*/{pattern}"))
        
        # Validate each setup script
        for script_path in setup_scripts:
            result = self._validate_setup_script(script_path)
            results.append(result)
        
        # Validate README setup instructions
        readme_path = target_path / 'README.md'
        if readme_path.exists():
            readme_result = self._validate_readme_setup_instructions(readme_path)
            results.append(readme_result)
        
        # Validate Docker setup if present
        docker_compose_path = target_path / 'docker-compose.yml'
        if docker_compose_path.exists():
            docker_result = self._validate_docker_setup(docker_compose_path)
            results.append(docker_result)
        
        return results
    
    def _validate_setup_script(self, script_path: Path) -> SetupValidationResult:
        """Validate individual setup script"""
        start_time = datetime.now()
        
        try:
            content = script_path.read_text(encoding='utf-8', errors='ignore')
            
            # Basic validation checks
            issues = []
            steps_found = 0
            
            # Check for common setup patterns
            setup_patterns = [
                r'pip install',
                r'npm install',
                r'yarn install',
                r'go mod',
                r'make install',
                r'apt-get install',
                r'yum install'
            ]
            
            for pattern in setup_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    steps_found += 1
            
            # Check for error handling
            if not re.search(r'set -e|exit|error', content, re.IGNORECASE):
                issues.append("Script lacks error handling")
            
            # Check for documentation
            if len(content.strip()) > 0 and not re.search(r'^#.*', content, re.MULTILINE):
                issues.append("Script lacks comments or documentation")
            
            status = 'valid' if len(issues) == 0 else 'partial'
            
        except Exception as e:
            issues = [f"Cannot read script: {e}"]
            steps_found = 0
            status = 'invalid'
        
        execution_time = (datetime.now() - start_time).total_seconds()
        
        return SetupValidationResult(
            procedure_name=f"Setup script: {script_path.name}",
            status=status,
            steps_validated=steps_found,
            total_steps=max(steps_found, 1),
            issues_found=issues,
            execution_time_seconds=execution_time
        )
    
    def _validate_readme_setup_instructions(self, readme_path: Path) -> SetupValidationResult:
        """Validate setup instructions in README"""
        start_time = datetime.now()
        
        try:
            content = readme_path.read_text(encoding='utf-8', errors='ignore')
            
            issues = []
            steps_found = 0
            
            # Look for installation/setup sections
            has_installation = self._has_section(content, 'Installation') or self._has_section(content, 'Setup')
            if not has_installation:
                issues.append("No installation/setup section found")
            
            # Look for prerequisites
            has_prerequisites = self._has_section(content, 'Prerequisites') or self._has_section(content, 'Requirements')
            if not has_prerequisites:
                issues.append("No prerequisites section found")
            
            # Count setup steps (code blocks or numbered lists)
            code_blocks = len(re.findall(r'```[\s\S]*?```', content))
            numbered_steps = len(re.findall(r'^\d+\.', content, re.MULTILINE))
            steps_found = code_blocks + numbered_steps
            
            # Check for usage examples
            has_usage = self._has_section(content, 'Usage') or self._has_section(content, 'Examples')
            if not has_usage:
                issues.append("No usage examples found")
            
            status = 'valid' if len(issues) == 0 else 'partial'
            
        except Exception as e:
            issues = [f"Cannot read README: {e}"]
            steps_found = 0
            status = 'invalid'
        
        execution_time = (datetime.now() - start_time).total_seconds()
        
        return SetupValidationResult(
            procedure_name="README setup instructions",
            status=status,
            steps_validated=steps_found,
            total_steps=max(steps_found, 3),  # Expect at least 3 setup steps
            issues_found=issues,
            execution_time_seconds=execution_time
        )
    
    def _validate_docker_setup(self, docker_compose_path: Path) -> SetupValidationResult:
        """Validate Docker setup configuration"""
        start_time = datetime.now()
        
        try:
            content = docker_compose_path.read_text(encoding='utf-8', errors='ignore')
            
            issues = []
            steps_found = 0
            
            # Check for services
            services_count = len(re.findall(r'^\s+\w+:', content, re.MULTILINE))
            steps_found = services_count
            
            # Check for security issues
            if 'privileged: true' in content:
                issues.append("Privileged containers detected - security risk")
            
            if re.search(r':\s*latest\s*$', content, re.MULTILINE):
                issues.append("Using 'latest' tags - not recommended for production")
            
            # Check for environment variables
            if '.env' not in content and 'environment:' not in content:
                issues.append("No environment variable configuration found")
            
            # Check for volumes
            if 'volumes:' not in content:
                issues.append("No volume configuration found - data may not persist")
            
            status = 'valid' if len(issues) == 0 else 'partial'
            
        except Exception as e:
            issues = [f"Cannot read docker-compose.yml: {e}"]
            steps_found = 0
            status = 'invalid'
        
        execution_time = (datetime.now() - start_time).total_seconds()
        
        return SetupValidationResult(
            procedure_name="Docker Compose setup",
            status=status,
            steps_validated=steps_found,
            total_steps=max(steps_found, 1),
            issues_found=issues,
            execution_time_seconds=execution_time
        )
    
    def _assess_deployment_readiness(self, target_path: Path) -> DeploymentReadinessAssessment:
        """Assess deployment readiness with security and operational considerations"""
        
        # Security assessment
        security_assessment = self._assess_security_readiness(target_path)
        
        # Operational assessment
        operational_assessment = self._assess_operational_readiness(target_path)
        
        # Identify missing requirements
        missing_requirements = []
        
        # Check for essential files
        essential_files = ['.gitignore', 'requirements.txt', 'README.md']
        for file_name in essential_files:
            if not (target_path / file_name).exists():
                missing_requirements.append(f"Missing {file_name}")
        
        # Check for security files
        security_files = ['.env.example', 'SECURITY.md']
        missing_security = [f for f in security_files if not (target_path / f).exists()]
        if missing_security:
            missing_requirements.extend([f"Missing {f}" for f in missing_security])
        
        # Calculate readiness score
        security_score = security_assessment.get('score', 0.5)
        operational_score = operational_assessment.get('score', 0.5)
        completeness_score = 1.0 - (len(missing_requirements) * 0.1)
        
        readiness_score = (security_score * 0.4 + operational_score * 0.4 + completeness_score * 0.2)
        readiness_score = max(0.0, min(1.0, readiness_score))
        
        # Determine overall readiness
        if readiness_score >= 0.8:
            overall_readiness = 'ready'
        elif readiness_score >= 0.6:
            overall_readiness = 'needs_work'
        else:
            overall_readiness = 'not_ready'
        
        # Generate recommendations
        recommendations = []
        recommendations.extend(security_assessment.get('recommendations', []))
        recommendations.extend(operational_assessment.get('recommendations', []))
        
        if missing_requirements:
            recommendations.append("Address missing requirements before deployment")
        
        return DeploymentReadinessAssessment(
            overall_readiness=overall_readiness,
            readiness_score=readiness_score,
            security_assessment=security_assessment,
            operational_assessment=operational_assessment,
            missing_requirements=missing_requirements,
            recommendations=recommendations
        )
    
    def _assess_security_readiness(self, target_path: Path) -> Dict[str, Any]:
        """Assess security readiness for deployment"""
        security_issues = []
        security_strengths = []
        
        # Check for .gitignore
        gitignore_path = target_path / '.gitignore'
        if gitignore_path.exists():
            security_strengths.append("Has .gitignore file")
            
            # Check .gitignore content
            try:
                gitignore_content = gitignore_path.read_text()
                sensitive_patterns = ['.env', '*.key', '*.pem', 'secrets', 'credentials']
                missing_patterns = [p for p in sensitive_patterns if p not in gitignore_content]
                if missing_patterns:
                    security_issues.append(f"Missing .gitignore patterns: {', '.join(missing_patterns)}")
            except Exception:
                security_issues.append("Cannot read .gitignore file")
        else:
            security_issues.append("Missing .gitignore file")
        
        # Check for security documentation
        security_md = target_path / 'SECURITY.md'
        if security_md.exists():
            security_strengths.append("Has security documentation")
        else:
            security_issues.append("Missing SECURITY.md file")
        
        # Check for environment variable examples
        env_example = target_path / '.env.example'
        if env_example.exists():
            security_strengths.append("Has environment variable template")
        else:
            security_issues.append("Missing .env.example file")
        
        # Check for hardcoded secrets (basic scan)
        secret_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']'
        ]
        
        hardcoded_secrets_found = False
        for file_path in target_path.rglob('*.py'):
            if file_path.is_file():
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    for pattern in secret_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            hardcoded_secrets_found = True
                            break
                    if hardcoded_secrets_found:
                        break
                except Exception:
                    continue
        
        if hardcoded_secrets_found:
            security_issues.append("Potential hardcoded secrets detected")
        else:
            security_strengths.append("No obvious hardcoded secrets found")
        
        # Calculate security score
        total_checks = len(security_issues) + len(security_strengths)
        if total_checks > 0:
            security_score = len(security_strengths) / total_checks
        else:
            security_score = 0.5
        
        recommendations = []
        if security_issues:
            recommendations.extend([f"Fix: {issue}" for issue in security_issues])
        
        return {
            'score': security_score,
            'issues': security_issues,
            'strengths': security_strengths,
            'recommendations': recommendations
        }
    
    def _assess_operational_readiness(self, target_path: Path) -> Dict[str, Any]:
        """Assess operational readiness for deployment"""
        operational_issues = []
        operational_strengths = []
        
        # Check for dependency management
        dependency_files = ['requirements.txt', 'package.json', 'go.mod', 'Pipfile']
        has_dependencies = any((target_path / f).exists() for f in dependency_files)
        
        if has_dependencies:
            operational_strengths.append("Has dependency management")
        else:
            operational_issues.append("No dependency management files found")
        
        # Check for containerization
        docker_files = ['Dockerfile', 'docker-compose.yml']
        has_docker = any((target_path / f).exists() for f in docker_files)
        
        if has_docker:
            operational_strengths.append("Has containerization support")
        else:
            operational_issues.append("No containerization files found")
        
        # Check for configuration management
        config_files = ['config.yaml', 'config.json', '.env.example', 'settings.py']
        has_config = any((target_path / f).exists() for f in config_files)
        
        if has_config:
            operational_strengths.append("Has configuration management")
        else:
            operational_issues.append("No configuration management found")
        
        # Check for logging configuration
        log_patterns = ['logging', 'log', 'logger']
        has_logging = False
        
        for pattern in log_patterns:
            if list(target_path.rglob(f'*{pattern}*')):
                has_logging = True
                break
        
        if has_logging:
            operational_strengths.append("Has logging configuration")
        else:
            operational_issues.append("No logging configuration found")
        
        # Check for health checks
        health_check_files = ['health.py', 'healthcheck.py', 'health_check.py']
        has_health_check = any((target_path / f).exists() for f in health_check_files)
        
        if has_health_check:
            operational_strengths.append("Has health check implementation")
        
        # Calculate operational score
        total_checks = len(operational_issues) + len(operational_strengths)
        if total_checks > 0:
            operational_score = len(operational_strengths) / total_checks
        else:
            operational_score = 0.5
        
        recommendations = []
        if operational_issues:
            recommendations.extend([f"Add: {issue.replace('No ', '').replace(' found', '')}" for issue in operational_issues])
        
        return {
            'score': operational_score,
            'issues': operational_issues,
            'strengths': operational_strengths,
            'recommendations': recommendations
        }
    
    def _check_governance_compliance(self, target_path: Path) -> Dict[str, Any]:
        """Check governance and compliance documentation"""
        compliance_status = {}
        
        # Check for SDD compliance
        sdd_files = ['requirements.md', 'design.md', 'tasks.md']
        sdd_compliance = {
            'has_all_files': all((target_path / f).exists() for f in sdd_files),
            'missing_files': [f for f in sdd_files if not (target_path / f).exists()],
            'compliance_score': sum(1 for f in sdd_files if (target_path / f).exists()) / len(sdd_files)
        }
        compliance_status['sdd'] = sdd_compliance
        
        # Check for license compliance
        license_files = ['LICENSE', 'LICENSE.txt', 'LICENSE.md']
        has_license = any((target_path / f).exists() for f in license_files)
        compliance_status['license'] = {
            'has_license': has_license,
            'compliance_score': 1.0 if has_license else 0.0
        }
        
        # Check for contribution guidelines
        contrib_files = ['CONTRIBUTING.md', 'CONTRIBUTING.txt']
        has_contrib = any((target_path / f).exists() for f in contrib_files)
        compliance_status['contributing'] = {
            'has_guidelines': has_contrib,
            'compliance_score': 1.0 if has_contrib else 0.5  # Not critical
        }
        
        # Overall compliance score
        scores = [status.get('compliance_score', 0) for status in compliance_status.values()]
        overall_compliance = sum(scores) / len(scores) if scores else 0.0
        compliance_status['overall_score'] = overall_compliance
        
        return compliance_status
    
    def _calculate_documentation_quality_score(self, gaps: List[DocumentationGap], 
                                             setup_results: List[SetupValidationResult],
                                             deployment_readiness: DeploymentReadinessAssessment) -> float:
        """Calculate overall documentation quality score"""
        
        # Documentation completeness score
        critical_gaps = len([g for g in gaps if g.severity == 'critical'])
        high_gaps = len([g for g in gaps if g.severity == 'high'])
        total_gaps = len(gaps)
        
        if total_gaps == 0:
            completeness_score = 1.0
        else:
            # Weight critical and high severity gaps more heavily
            weighted_gaps = critical_gaps * 3 + high_gaps * 2 + (total_gaps - critical_gaps - high_gaps)
            completeness_score = max(0.0, 1.0 - (weighted_gaps * 0.1))
        
        # Setup validation score
        if setup_results:
            valid_setups = len([r for r in setup_results if r.status == 'valid'])
            setup_score = valid_setups / len(setup_results)
        else:
            setup_score = 0.5  # Neutral if no setup procedures found
        
        # Deployment readiness score
        deployment_score = deployment_readiness.readiness_score
        
        # Weighted average
        quality_score = (completeness_score * 0.4 + setup_score * 0.3 + deployment_score * 0.3)
        
        return round(quality_score, 2)
    
    def _generate_analysis_summary(self, gaps: List[DocumentationGap],
                                 setup_results: List[SetupValidationResult],
                                 deployment_readiness: DeploymentReadinessAssessment,
                                 quality_score: float) -> str:
        """Generate analysis summary"""
        
        critical_gaps = len([g for g in gaps if g.severity == 'critical'])
        valid_setups = len([r for r in setup_results if r.status == 'valid'])
        
        summary = f"""Documentation Analysis Summary:
- Quality Score: {quality_score:.1%}
- Documentation Gaps: {len(gaps)} total ({critical_gaps} critical)
- Setup Procedures: {valid_setups}/{len(setup_results)} valid
- Deployment Readiness: {deployment_readiness.overall_readiness} ({deployment_readiness.readiness_score:.1%})
- Security Assessment: {deployment_readiness.security_assessment.get('score', 0):.1%}
- Operational Readiness: {deployment_readiness.operational_assessment.get('score', 0):.1%}
"""
        
        if critical_gaps > 0:
            summary += f"\n⚠️  {critical_gaps} critical documentation issues require immediate attention"
        
        if deployment_readiness.overall_readiness == 'not_ready':
            summary += f"\n❌ System not ready for deployment - address {len(deployment_readiness.missing_requirements)} missing requirements"
        elif deployment_readiness.overall_readiness == 'needs_work':
            summary += f"\n⚠️  System needs work before deployment"
        else:
            summary += f"\n✅ System appears ready for deployment"
        
        return summary