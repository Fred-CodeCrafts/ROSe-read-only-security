"""
Deployment Readiness Analyzer

Provides comprehensive deployment readiness analysis with security and operational assessments.
Validates deployment configurations, infrastructure requirements, and operational procedures.
"""

import os
import json
import logging
import subprocess
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import re


@dataclass
class DeploymentIssue:
    """Represents a deployment readiness issue"""
    issue_id: str
    category: str  # 'security', 'operational', 'configuration', 'infrastructure'
    severity: str  # 'critical', 'high', 'medium', 'low'
    description: str
    file_path: Optional[str] = None
    remediation_steps: List[str] = field(default_factory=list)
    impact: str = "unknown"  # 'deployment_blocking', 'performance', 'security_risk', 'operational'


@dataclass
class InfrastructureRequirement:
    """Infrastructure requirement for deployment"""
    requirement_id: str
    category: str  # 'compute', 'storage', 'network', 'security'
    description: str
    required: bool = True
    current_status: str = "unknown"  # 'met', 'not_met', 'unknown'
    recommendations: List[str] = field(default_factory=list)


@dataclass
class SecurityAssessment:
    """Security assessment for deployment"""
    assessment_id: str
    security_score: float  # 0.0 to 1.0
    security_issues: List[DeploymentIssue] = field(default_factory=list)
    security_controls: List[str] = field(default_factory=list)
    compliance_status: Dict[str, str] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class OperationalAssessment:
    """Operational assessment for deployment"""
    assessment_id: str
    operational_score: float  # 0.0 to 1.0
    operational_issues: List[DeploymentIssue] = field(default_factory=list)
    monitoring_readiness: str = "unknown"  # 'ready', 'partial', 'not_ready'
    backup_readiness: str = "unknown"
    scaling_readiness: str = "unknown"
    recommendations: List[str] = field(default_factory=list)


@dataclass
class DeploymentReadinessReport:
    """Comprehensive deployment readiness report"""
    analysis_id: str
    timestamp: datetime
    target_path: str
    overall_readiness: str  # 'ready', 'needs_work', 'not_ready'
    readiness_score: float  # 0.0 to 1.0
    security_assessment: SecurityAssessment
    operational_assessment: OperationalAssessment
    infrastructure_requirements: List[InfrastructureRequirement]
    deployment_issues: List[DeploymentIssue]
    recommendations: List[str]
    summary: str


class DeploymentAnalyzer:
    """
    Deployment Readiness Analyzer
    
    Analyzes deployment readiness with comprehensive security and operational assessments.
    Validates infrastructure requirements, security configurations, and operational procedures.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Security configuration patterns
        self.security_patterns = {
            'secrets_management': [
                r'\.env\.example',
                r'secrets\.yaml',
                r'vault',
                r'secret.*manager'
            ],
            'ssl_tls': [
                r'ssl',
                r'tls',
                r'certificate',
                r'https'
            ],
            'authentication': [
                r'auth',
                r'jwt',
                r'oauth',
                r'saml'
            ],
            'encryption': [
                r'encrypt',
                r'cipher',
                r'crypto'
            ]
        }
        
        # Infrastructure file patterns
        self.infrastructure_files = {
            'docker': ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'],
            'kubernetes': ['*.yaml', '*.yml', 'kustomization.yaml'],
            'terraform': ['*.tf', 'terraform.tfvars'],
            'ansible': ['playbook.yml', 'ansible.cfg'],
            'helm': ['Chart.yaml', 'values.yaml']
        }
        
        # Operational readiness indicators
        self.operational_indicators = {
            'monitoring': ['prometheus', 'grafana', 'datadog', 'newrelic', 'monitoring'],
            'logging': ['logging', 'logs', 'logstash', 'fluentd', 'syslog'],
            'backup': ['backup', 'snapshot', 'restore', 'recovery'],
            'health_checks': ['health', 'readiness', 'liveness', 'probe'],
            'scaling': ['autoscaling', 'hpa', 'scaling', 'replicas']
        }
    
    def analyze_deployment_readiness(self, target_path: str, 
                                   deployment_environment: str = "production") -> DeploymentReadinessReport:
        """
        Analyze deployment readiness with comprehensive assessments
        
        Args:
            target_path: Path to analyze
            deployment_environment: Target deployment environment (development, staging, production)
            
        Returns:
            DeploymentReadinessReport with comprehensive analysis
        """
        self.logger.info(f"Starting deployment readiness analysis for {target_path}")
        
        analysis_id = f"deploy_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        target_path_obj = Path(target_path)
        
        # Perform security assessment
        security_assessment = self._assess_deployment_security(target_path_obj, deployment_environment)
        
        # Perform operational assessment
        operational_assessment = self._assess_operational_readiness(target_path_obj, deployment_environment)
        
        # Analyze infrastructure requirements
        infrastructure_requirements = self._analyze_infrastructure_requirements(target_path_obj)
        
        # Identify deployment issues
        deployment_issues = self._identify_deployment_issues(target_path_obj, deployment_environment)
        
        # Calculate overall readiness
        readiness_score, overall_readiness = self._calculate_overall_readiness(
            security_assessment, operational_assessment, deployment_issues
        )
        
        # Generate recommendations
        recommendations = self._generate_deployment_recommendations(
            security_assessment, operational_assessment, deployment_issues
        )
        
        # Generate summary
        summary = self._generate_deployment_summary(
            overall_readiness, readiness_score, security_assessment, operational_assessment
        )
        
        report = DeploymentReadinessReport(
            analysis_id=analysis_id,
            timestamp=datetime.now(),
            target_path=target_path,
            overall_readiness=overall_readiness,
            readiness_score=readiness_score,
            security_assessment=security_assessment,
            operational_assessment=operational_assessment,
            infrastructure_requirements=infrastructure_requirements,
            deployment_issues=deployment_issues,
            recommendations=recommendations,
            summary=summary
        )
        
        self.logger.info(f"Deployment readiness analysis completed: {overall_readiness} ({readiness_score:.1%})")
        return report
    
    def _assess_deployment_security(self, target_path: Path, environment: str) -> SecurityAssessment:
        """Assess security readiness for deployment"""
        assessment_id = f"security_{datetime.now().strftime('%H%M%S')}"
        security_issues = []
        security_controls = []
        compliance_status = {}
        
        # Check for secrets management
        secrets_files = ['.env.example', 'secrets.yaml.example', 'vault.yaml']
        has_secrets_management = any((target_path / f).exists() for f in secrets_files)
        
        if has_secrets_management:
            security_controls.append("Secrets management configuration found")
        else:
            security_issues.append(DeploymentIssue(
                issue_id="missing_secrets_management",
                category="security",
                severity="high" if environment == "production" else "medium",
                description="No secrets management configuration found",
                remediation_steps=[
                    "Create .env.example file with required environment variables",
                    "Implement secure secrets management (e.g., HashiCorp Vault, AWS Secrets Manager)"
                ],
                impact="security_risk"
            ))
        
        # Check for SSL/TLS configuration
        ssl_indicators = ['ssl', 'tls', 'https', 'certificate']
        ssl_files = list(target_path.rglob('*'))
        has_ssl_config = any(
            any(indicator in str(f).lower() for indicator in ssl_indicators)
            for f in ssl_files if f.is_file()
        )
        
        if has_ssl_config:
            security_controls.append("SSL/TLS configuration detected")
        elif environment == "production":
            security_issues.append(DeploymentIssue(
                issue_id="missing_ssl_config",
                category="security",
                severity="critical",
                description="No SSL/TLS configuration found for production deployment",
                remediation_steps=[
                    "Configure SSL/TLS certificates",
                    "Enable HTTPS for all endpoints",
                    "Implement certificate management"
                ],
                impact="security_risk"
            ))
        
        # Check for authentication configuration
        auth_patterns = ['auth', 'jwt', 'oauth', 'saml', 'authentication']
        has_auth_config = any(
            any(pattern in str(f).lower() for pattern in auth_patterns)
            for f in target_path.rglob('*') if f.is_file()
        )
        
        if has_auth_config:
            security_controls.append("Authentication configuration found")
        else:
            security_issues.append(DeploymentIssue(
                issue_id="missing_auth_config",
                category="security",
                severity="high",
                description="No authentication configuration found",
                remediation_steps=[
                    "Implement authentication mechanism",
                    "Configure authorization controls",
                    "Set up user management"
                ],
                impact="security_risk"
            ))
        
        # Check for security headers and configurations
        security_config_files = ['security.yaml', 'security.json', 'nginx.conf', 'apache.conf']
        has_security_config = any((target_path / f).exists() for f in security_config_files)
        
        if has_security_config:
            security_controls.append("Security configuration files found")
        
        # Check for firewall/network security
        network_security_files = ['firewall.rules', 'iptables.conf', 'security-groups.yaml']
        has_network_security = any((target_path / f).exists() for f in network_security_files)
        
        if has_network_security:
            security_controls.append("Network security configuration found")
        
        # Calculate security score
        total_checks = len(security_issues) + len(security_controls)
        if total_checks > 0:
            security_score = len(security_controls) / total_checks
        else:
            security_score = 0.5
        
        # Adjust score based on environment
        if environment == "production":
            # Production requires higher security standards
            critical_issues = len([i for i in security_issues if i.severity == "critical"])
            if critical_issues > 0:
                security_score *= 0.5  # Significantly reduce score for critical issues
        
        # Compliance status
        compliance_status = {
            "secrets_management": "compliant" if has_secrets_management else "non_compliant",
            "ssl_tls": "compliant" if has_ssl_config or environment != "production" else "non_compliant",
            "authentication": "compliant" if has_auth_config else "partial"
        }
        
        # Generate security recommendations
        recommendations = []
        for issue in security_issues:
            recommendations.extend(issue.remediation_steps[:1])  # First remediation step
        
        if environment == "production":
            recommendations.extend([
                "Implement comprehensive security monitoring",
                "Regular security audits and penetration testing",
                "Establish incident response procedures"
            ])
        
        return SecurityAssessment(
            assessment_id=assessment_id,
            security_score=security_score,
            security_issues=security_issues,
            security_controls=security_controls,
            compliance_status=compliance_status,
            recommendations=recommendations
        )
    
    def _assess_operational_readiness(self, target_path: Path, environment: str) -> OperationalAssessment:
        """Assess operational readiness for deployment"""
        assessment_id = f"operational_{datetime.now().strftime('%H%M%S')}"
        operational_issues = []
        
        # Check monitoring readiness
        monitoring_readiness = self._check_monitoring_readiness(target_path)
        
        # Check backup readiness
        backup_readiness = self._check_backup_readiness(target_path)
        
        # Check scaling readiness
        scaling_readiness = self._check_scaling_readiness(target_path)
        
        # Check for health checks
        health_check_files = ['health.py', 'healthcheck.py', 'health_check.go', 'health.js']
        has_health_checks = any((target_path / f).exists() for f in health_check_files)
        
        if not has_health_checks:
            # Check for health check patterns in code
            health_patterns = ['health', 'readiness', 'liveness', '/ping', '/status']
            has_health_patterns = False
            
            for file_path in target_path.rglob('*'):
                if file_path.is_file() and file_path.suffix in ['.py', '.go', '.js', '.ts', '.java']:
                    try:
                        content = file_path.read_text(encoding='utf-8', errors='ignore')
                        if any(pattern in content.lower() for pattern in health_patterns):
                            has_health_patterns = True
                            break
                    except Exception:
                        continue
            
            if not has_health_patterns:
                operational_issues.append(DeploymentIssue(
                    issue_id="missing_health_checks",
                    category="operational",
                    severity="high" if environment == "production" else "medium",
                    description="No health check endpoints found",
                    remediation_steps=[
                        "Implement health check endpoints",
                        "Add readiness and liveness probes",
                        "Configure monitoring for health status"
                    ],
                    impact="operational"
                ))
        
        # Check for logging configuration
        logging_files = ['logging.yaml', 'log4j.properties', 'logback.xml']
        has_logging_config = any((target_path / f).exists() for f in logging_files)
        
        if not has_logging_config:
            operational_issues.append(DeploymentIssue(
                issue_id="missing_logging_config",
                category="operational",
                severity="medium",
                description="No logging configuration found",
                remediation_steps=[
                    "Configure structured logging",
                    "Set appropriate log levels",
                    "Implement log rotation"
                ],
                impact="operational"
            ))
        
        # Check for configuration management
        config_files = ['config.yaml', 'application.properties', 'settings.py']
        has_config_management = any((target_path / f).exists() for f in config_files)
        
        if not has_config_management:
            operational_issues.append(DeploymentIssue(
                issue_id="missing_config_management",
                category="configuration",
                severity="medium",
                description="No configuration management found",
                remediation_steps=[
                    "Implement configuration management",
                    "Separate configuration from code",
                    "Use environment-specific configurations"
                ],
                impact="operational"
            ))
        
        # Calculate operational score
        readiness_scores = {
            'monitoring': 1.0 if monitoring_readiness == "ready" else 0.5 if monitoring_readiness == "partial" else 0.0,
            'backup': 1.0 if backup_readiness == "ready" else 0.5 if backup_readiness == "partial" else 0.0,
            'scaling': 1.0 if scaling_readiness == "ready" else 0.5 if scaling_readiness == "partial" else 0.0,
            'health_checks': 1.0 if has_health_checks else 0.0,
            'logging': 1.0 if has_logging_config else 0.0,
            'config': 1.0 if has_config_management else 0.0
        }
        
        operational_score = sum(readiness_scores.values()) / len(readiness_scores)
        
        # Generate operational recommendations
        recommendations = []
        for issue in operational_issues:
            recommendations.extend(issue.remediation_steps[:1])
        
        if monitoring_readiness != "ready":
            recommendations.append("Implement comprehensive monitoring and alerting")
        
        if backup_readiness != "ready":
            recommendations.append("Establish backup and recovery procedures")
        
        return OperationalAssessment(
            assessment_id=assessment_id,
            operational_score=operational_score,
            operational_issues=operational_issues,
            monitoring_readiness=monitoring_readiness,
            backup_readiness=backup_readiness,
            scaling_readiness=scaling_readiness,
            recommendations=recommendations
        )
    
    def _check_monitoring_readiness(self, target_path: Path) -> str:
        """Check monitoring readiness"""
        monitoring_files = [
            'prometheus.yml', 'grafana.json', 'datadog.yaml',
            'newrelic.yml', 'monitoring.yaml'
        ]
        
        has_monitoring_config = any((target_path / f).exists() for f in monitoring_files)
        
        # Check for monitoring patterns in code
        monitoring_patterns = ['metrics', 'prometheus', 'grafana', 'monitoring']
        has_monitoring_code = False
        
        for file_path in target_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.go', '.js', '.ts']:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    if any(pattern in content.lower() for pattern in monitoring_patterns):
                        has_monitoring_code = True
                        break
                except Exception:
                    continue
        
        if has_monitoring_config and has_monitoring_code:
            return "ready"
        elif has_monitoring_config or has_monitoring_code:
            return "partial"
        else:
            return "not_ready"
    
    def _check_backup_readiness(self, target_path: Path) -> str:
        """Check backup and recovery readiness"""
        backup_files = ['backup.sh', 'backup.py', 'backup.yaml', 'recovery.md']
        has_backup_config = any((target_path / f).exists() for f in backup_files)
        
        # Check for database backup configurations
        db_backup_patterns = ['pg_dump', 'mysqldump', 'backup', 'snapshot']
        has_db_backup = False
        
        for file_path in target_path.rglob('*'):
            if file_path.is_file():
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    if any(pattern in content.lower() for pattern in db_backup_patterns):
                        has_db_backup = True
                        break
                except Exception:
                    continue
        
        if has_backup_config and has_db_backup:
            return "ready"
        elif has_backup_config or has_db_backup:
            return "partial"
        else:
            return "not_ready"
    
    def _check_scaling_readiness(self, target_path: Path) -> str:
        """Check scaling readiness"""
        scaling_files = ['hpa.yaml', 'autoscaling.yaml', 'scaling.yaml']
        has_scaling_config = any((target_path / f).exists() for f in scaling_files)
        
        # Check for containerization (prerequisite for scaling)
        container_files = ['Dockerfile', 'docker-compose.yml']
        has_containers = any((target_path / f).exists() for f in container_files)
        
        # Check for Kubernetes configurations
        k8s_files = list(target_path.glob('*.yaml')) + list(target_path.glob('*.yml'))
        has_k8s_config = any('kind:' in f.read_text(errors='ignore') for f in k8s_files if f.is_file())
        
        if has_scaling_config and (has_containers or has_k8s_config):
            return "ready"
        elif has_containers or has_k8s_config:
            return "partial"
        else:
            return "not_ready"
    
    def _analyze_infrastructure_requirements(self, target_path: Path) -> List[InfrastructureRequirement]:
        """Analyze infrastructure requirements"""
        requirements = []
        
        # Check for compute requirements
        has_dockerfile = (target_path / 'Dockerfile').exists()
        if has_dockerfile:
            requirements.append(InfrastructureRequirement(
                requirement_id="container_runtime",
                category="compute",
                description="Container runtime (Docker/Podman) required",
                required=True,
                current_status="unknown",
                recommendations=["Ensure container runtime is available in deployment environment"]
            ))
        
        # Check for database requirements
        db_patterns = ['postgres', 'mysql', 'mongodb', 'redis', 'database']
        has_database = any(
            any(pattern in str(f).lower() for pattern in db_patterns)
            for f in target_path.rglob('*') if f.is_file()
        )
        
        if has_database:
            requirements.append(InfrastructureRequirement(
                requirement_id="database_service",
                category="storage",
                description="Database service required",
                required=True,
                current_status="unknown",
                recommendations=["Provision and configure database service"]
            ))
        
        # Check for load balancer requirements
        lb_patterns = ['nginx', 'apache', 'haproxy', 'load.*balancer']
        has_load_balancer = any(
            any(re.search(pattern, str(f), re.IGNORECASE) for pattern in lb_patterns)
            for f in target_path.rglob('*') if f.is_file()
        )
        
        if has_load_balancer:
            requirements.append(InfrastructureRequirement(
                requirement_id="load_balancer",
                category="network",
                description="Load balancer required",
                required=True,
                current_status="unknown",
                recommendations=["Configure load balancer for high availability"]
            ))
        
        # Check for storage requirements
        storage_patterns = ['volume', 'storage', 'persistent', 'pvc']
        has_storage = any(
            any(pattern in str(f).lower() for pattern in storage_patterns)
            for f in target_path.rglob('*') if f.is_file()
        )
        
        if has_storage:
            requirements.append(InfrastructureRequirement(
                requirement_id="persistent_storage",
                category="storage",
                description="Persistent storage required",
                required=True,
                current_status="unknown",
                recommendations=["Provision persistent storage volumes"]
            ))
        
        return requirements
    
    def _identify_deployment_issues(self, target_path: Path, environment: str) -> List[DeploymentIssue]:
        """Identify deployment-blocking issues"""
        issues = []
        
        # Check for missing essential files
        essential_files = {
            'README.md': 'Documentation',
            'requirements.txt': 'Python dependencies',
            'package.json': 'Node.js dependencies',
            'go.mod': 'Go dependencies'
        }
        
        # At least one dependency file should exist
        has_dependencies = any((target_path / f).exists() for f in essential_files.keys() if f != 'README.md')
        
        if not has_dependencies:
            issues.append(DeploymentIssue(
                issue_id="missing_dependencies",
                category="configuration",
                severity="critical",
                description="No dependency management files found",
                remediation_steps=["Add appropriate dependency management file (requirements.txt, package.json, etc.)"],
                impact="deployment_blocking"
            ))
        
        # Check for hardcoded configurations
        config_patterns = [
            r'localhost',
            r'127\.0\.0\.1',
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']'
        ]
        
        hardcoded_configs = []
        for file_path in target_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.ts', '.go', '.java', '.yaml', '.yml', '.json']:
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    for pattern in config_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            hardcoded_configs.append(str(file_path))
                            break
                except Exception:
                    continue
        
        if hardcoded_configs:
            issues.append(DeploymentIssue(
                issue_id="hardcoded_configurations",
                category="configuration",
                severity="high",
                description=f"Hardcoded configurations found in {len(hardcoded_configs)} files",
                remediation_steps=[
                    "Replace hardcoded values with environment variables",
                    "Use configuration management system",
                    "Create environment-specific configuration files"
                ],
                impact="security_risk"
            ))
        
        # Check for missing .gitignore
        if not (target_path / '.gitignore').exists():
            issues.append(DeploymentIssue(
                issue_id="missing_gitignore",
                category="configuration",
                severity="medium",
                description="Missing .gitignore file",
                remediation_steps=["Create .gitignore file to exclude sensitive files and build artifacts"],
                impact="security_risk"
            ))
        
        return issues
    
    def _calculate_overall_readiness(self, security_assessment: SecurityAssessment,
                                   operational_assessment: OperationalAssessment,
                                   deployment_issues: List[DeploymentIssue]) -> Tuple[float, str]:
        """Calculate overall deployment readiness"""
        
        # Weight the assessments
        security_weight = 0.4
        operational_weight = 0.4
        issues_weight = 0.2
        
        # Calculate issues score
        critical_issues = len([i for i in deployment_issues if i.severity == "critical"])
        high_issues = len([i for i in deployment_issues if i.severity == "high"])
        
        if critical_issues > 0:
            issues_score = 0.0  # Critical issues block deployment
        elif high_issues > 0:
            issues_score = max(0.0, 1.0 - (high_issues * 0.3))
        else:
            issues_score = max(0.0, 1.0 - (len(deployment_issues) * 0.1))
        
        # Calculate weighted score
        readiness_score = (
            security_assessment.security_score * security_weight +
            operational_assessment.operational_score * operational_weight +
            issues_score * issues_weight
        )
        
        # Determine overall readiness
        if readiness_score >= 0.8 and critical_issues == 0:
            overall_readiness = "ready"
        elif readiness_score >= 0.6 and critical_issues == 0:
            overall_readiness = "needs_work"
        else:
            overall_readiness = "not_ready"
        
        return round(readiness_score, 2), overall_readiness
    
    def _generate_deployment_recommendations(self, security_assessment: SecurityAssessment,
                                           operational_assessment: OperationalAssessment,
                                           deployment_issues: List[DeploymentIssue]) -> List[str]:
        """Generate deployment recommendations"""
        recommendations = []
        
        # Critical issues first
        critical_issues = [i for i in deployment_issues if i.severity == "critical"]
        if critical_issues:
            recommendations.append(f"Address {len(critical_issues)} critical deployment-blocking issues")
            for issue in critical_issues:
                recommendations.extend(issue.remediation_steps[:1])
        
        # Security recommendations
        recommendations.extend(security_assessment.recommendations[:3])
        
        # Operational recommendations
        recommendations.extend(operational_assessment.recommendations[:3])
        
        # General deployment recommendations
        recommendations.extend([
            "Implement comprehensive testing in staging environment",
            "Establish rollback procedures and disaster recovery plan",
            "Create deployment runbooks and operational documentation",
            "Set up monitoring and alerting for production deployment"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _generate_deployment_summary(self, overall_readiness: str, readiness_score: float,
                                   security_assessment: SecurityAssessment,
                                   operational_assessment: OperationalAssessment) -> str:
        """Generate deployment readiness summary"""
        
        summary = f"""Deployment Readiness Summary:
- Overall Readiness: {overall_readiness.replace('_', ' ').title()} ({readiness_score:.1%})
- Security Score: {security_assessment.security_score:.1%}
- Operational Score: {operational_assessment.operational_score:.1%}
- Security Issues: {len(security_assessment.security_issues)}
- Operational Issues: {len(operational_assessment.operational_issues)}
"""
        
        if overall_readiness == "ready":
            summary += "\n✅ System is ready for deployment"
        elif overall_readiness == "needs_work":
            summary += "\n⚠️  System needs improvements before deployment"
        else:
            summary += "\n❌ System is not ready for deployment - critical issues must be resolved"
        
        return summary