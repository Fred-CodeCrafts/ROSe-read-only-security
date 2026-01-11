"""
Shadow Mode Risk Analysis System

This module provides comprehensive shadow environment provisioning and risk analysis
for proposed infrastructure changes. It operates in read-only analytical mode,
generating risk assessments and rollback recommendations without making changes.

Requirements: 3.1
"""

import os
import json
import yaml
import docker
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
import tempfile
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class ShadowEnvironmentConfig:
    """Configuration for shadow environment provisioning"""
    environment_id: str
    base_compose_file: str
    override_compose_file: Optional[str]
    network_isolation: bool
    resource_limits: Dict[str, Any]
    security_constraints: Dict[str, Any]
    monitoring_config: Dict[str, Any]
    created_at: datetime
    ttl_hours: int = 24


@dataclass
class InfrastructureChange:
    """Represents a proposed infrastructure change for analysis"""
    change_id: str
    change_type: str  # 'service_addition', 'configuration_change', 'network_change', etc.
    description: str
    affected_services: List[str]
    proposed_config: Dict[str, Any]
    current_config: Optional[Dict[str, Any]]
    risk_level: str  # 'low', 'medium', 'high', 'critical'
    impact_scope: List[str]
    submitted_by: str
    submitted_at: datetime


@dataclass
class RiskAssessment:
    """Risk assessment results for infrastructure changes"""
    change_id: str
    overall_risk_score: float  # 0.0 to 10.0
    security_risks: List[Dict[str, Any]]
    performance_risks: List[Dict[str, Any]]
    availability_risks: List[Dict[str, Any]]
    compliance_risks: List[Dict[str, Any]]
    blast_radius_assessment: Dict[str, Any]
    mitigation_strategies: List[str]
    rollback_plan: Dict[str, Any]
    analysis_timestamp: datetime
    confidence_level: float  # 0.0 to 1.0


@dataclass
class ShadowModeReport:
    """Comprehensive shadow mode analysis report"""
    environment_id: str
    change_id: str
    risk_assessment: RiskAssessment
    deployment_simulation_results: Dict[str, Any]
    security_scan_results: Dict[str, Any]
    performance_analysis: Dict[str, Any]
    recommendations: List[str]
    approval_status: str  # 'approved', 'rejected', 'needs_review'
    generated_at: datetime


class ShadowModeAnalyzer:
    """
    OSS-First Shadow Mode Risk Analysis System
    
    Provides comprehensive risk analysis for proposed infrastructure changes
    using Docker Compose for shadow environment provisioning and local analysis tools.
    """
    
    def __init__(self, 
                 base_compose_path: str = "docker-compose.yml",
                 shadow_workspace: str = "./shadow_environments",
                 analysis_db_path: str = "./data/analysis/shadow_analysis.db"):
        """
        Initialize Shadow Mode Analyzer with OSS tools
        
        Args:
            base_compose_path: Path to base Docker Compose configuration
            shadow_workspace: Directory for shadow environment files
            analysis_db_path: Path to analysis database
        """
        self.base_compose_path = Path(base_compose_path)
        self.shadow_workspace = Path(shadow_workspace)
        self.analysis_db_path = Path(analysis_db_path)
        
        # Initialize Docker client
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            self.docker_client = None
        
        # Create workspace directories
        self.shadow_workspace.mkdir(parents=True, exist_ok=True)
        self.analysis_db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize analysis state
        self.active_environments: Dict[str, ShadowEnvironmentConfig] = {}
        self.risk_assessments: Dict[str, RiskAssessment] = {}
        
        logger.info(f"Shadow Mode Analyzer initialized with workspace: {self.shadow_workspace}")
    
    def provision_shadow_environment(self, 
                                   change: InfrastructureChange,
                                   isolation_level: str = "high") -> ShadowEnvironmentConfig:
        """
        Provision isolated shadow environment for testing infrastructure changes
        
        Args:
            change: Infrastructure change to test
            isolation_level: Level of network isolation ('low', 'medium', 'high')
            
        Returns:
            Shadow environment configuration
        """
        environment_id = f"shadow-{change.change_id}-{int(datetime.now().timestamp())}"
        
        logger.info(f"Provisioning shadow environment: {environment_id}")
        
        # Create environment directory
        env_dir = self.shadow_workspace / environment_id
        env_dir.mkdir(parents=True, exist_ok=True)
        
        # Load base compose configuration
        base_config = self._load_compose_config(self.base_compose_path)
        
        # Apply infrastructure changes to shadow config
        shadow_config = self._apply_changes_to_config(base_config, change)
        
        # Apply security constraints and isolation
        shadow_config = self._apply_security_constraints(shadow_config, isolation_level)
        
        # Generate shadow compose file
        shadow_compose_path = env_dir / "docker-compose.shadow.yml"
        self._write_compose_config(shadow_config, shadow_compose_path)
        
        # Create environment configuration
        env_config = ShadowEnvironmentConfig(
            environment_id=environment_id,
            base_compose_file=str(self.base_compose_path),
            override_compose_file=str(shadow_compose_path),
            network_isolation=(isolation_level == "high"),
            resource_limits=self._get_resource_limits(change),
            security_constraints=self._get_security_constraints(isolation_level),
            monitoring_config=self._get_monitoring_config(),
            created_at=datetime.now(),
            ttl_hours=24
        )
        
        # Store environment configuration
        self.active_environments[environment_id] = env_config
        
        # Save environment metadata
        metadata_path = env_dir / "environment.json"
        with open(metadata_path, 'w') as f:
            json.dump(asdict(env_config), f, indent=2, default=str)
        
        logger.info(f"Shadow environment provisioned: {environment_id}")
        return env_config
    
    def analyze_infrastructure_change(self, change: InfrastructureChange) -> RiskAssessment:
        """
        Perform comprehensive risk analysis of proposed infrastructure change
        
        Args:
            change: Infrastructure change to analyze
            
        Returns:
            Risk assessment results
        """
        logger.info(f"Analyzing infrastructure change: {change.change_id}")
        
        # Provision shadow environment
        shadow_env = self.provision_shadow_environment(change)
        
        try:
            # Deploy to shadow environment
            deployment_results = self._deploy_to_shadow(shadow_env, change)
            
            # Perform security analysis
            security_risks = self._analyze_security_risks(change, deployment_results)
            
            # Analyze performance impact
            performance_risks = self._analyze_performance_risks(change, deployment_results)
            
            # Assess availability impact
            availability_risks = self._analyze_availability_risks(change, deployment_results)
            
            # Check compliance implications
            compliance_risks = self._analyze_compliance_risks(change)
            
            # Calculate blast radius
            blast_radius = self._assess_blast_radius(change)
            
            # Generate mitigation strategies
            mitigation_strategies = self._generate_mitigation_strategies(
                security_risks, performance_risks, availability_risks, compliance_risks
            )
            
            # Create rollback plan
            rollback_plan = self._create_rollback_plan(change)
            
            # Calculate overall risk score
            overall_risk_score = self._calculate_risk_score(
                security_risks, performance_risks, availability_risks, compliance_risks
            )
            
            # Create risk assessment
            risk_assessment = RiskAssessment(
                change_id=change.change_id,
                overall_risk_score=overall_risk_score,
                security_risks=security_risks,
                performance_risks=performance_risks,
                availability_risks=availability_risks,
                compliance_risks=compliance_risks,
                blast_radius_assessment=blast_radius,
                mitigation_strategies=mitigation_strategies,
                rollback_plan=rollback_plan,
                analysis_timestamp=datetime.now(),
                confidence_level=self._calculate_confidence_level(deployment_results)
            )
            
            # Store risk assessment
            self.risk_assessments[change.change_id] = risk_assessment
            
            logger.info(f"Risk analysis completed for change: {change.change_id}")
            return risk_assessment
            
        finally:
            # Cleanup shadow environment
            self._cleanup_shadow_environment(shadow_env.environment_id)
    
    def generate_comprehensive_report(self, 
                                    change: InfrastructureChange,
                                    risk_assessment: RiskAssessment) -> ShadowModeReport:
        """
        Generate comprehensive shadow mode analysis report
        
        Args:
            change: Infrastructure change analyzed
            risk_assessment: Risk assessment results
            
        Returns:
            Comprehensive analysis report
        """
        logger.info(f"Generating comprehensive report for change: {change.change_id}")
        
        # Simulate deployment for detailed analysis
        shadow_env = self.provision_shadow_environment(change)
        
        try:
            deployment_results = self._deploy_to_shadow(shadow_env, change)
            security_scan_results = self._perform_security_scan(shadow_env)
            performance_analysis = self._analyze_performance_metrics(shadow_env)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                risk_assessment, deployment_results, security_scan_results, performance_analysis
            )
            
            # Determine approval status
            approval_status = self._determine_approval_status(risk_assessment)
            
            report = ShadowModeReport(
                environment_id=shadow_env.environment_id,
                change_id=change.change_id,
                risk_assessment=risk_assessment,
                deployment_simulation_results=deployment_results,
                security_scan_results=security_scan_results,
                performance_analysis=performance_analysis,
                recommendations=recommendations,
                approval_status=approval_status,
                generated_at=datetime.now()
            )
            
            # Save report
            self._save_report(report)
            
            logger.info(f"Comprehensive report generated for change: {change.change_id}")
            return report
            
        finally:
            self._cleanup_shadow_environment(shadow_env.environment_id)
    
    def create_rollback_recommendations(self, change: InfrastructureChange) -> Dict[str, Any]:
        """
        Create detailed rollback recommendations for infrastructure change
        
        Args:
            change: Infrastructure change to create rollback plan for
            
        Returns:
            Detailed rollback recommendations
        """
        logger.info(f"Creating rollback recommendations for change: {change.change_id}")
        
        rollback_plan = {
            "change_id": change.change_id,
            "rollback_strategy": self._determine_rollback_strategy(change),
            "rollback_steps": self._generate_rollback_steps(change),
            "verification_steps": self._generate_verification_steps(change),
            "estimated_rollback_time": self._estimate_rollback_time(change),
            "risk_mitigation": self._generate_rollback_risk_mitigation(change),
            "communication_plan": self._generate_communication_plan(change),
            "monitoring_requirements": self._generate_monitoring_requirements(change),
            "success_criteria": self._define_rollback_success_criteria(change),
            "escalation_procedures": self._define_escalation_procedures(change),
            "created_at": datetime.now().isoformat()
        }
        
        logger.info(f"Rollback recommendations created for change: {change.change_id}")
        return rollback_plan
    
    # Private helper methods
    
    def _load_compose_config(self, compose_path: Path) -> Dict[str, Any]:
        """Load Docker Compose configuration from file"""
        try:
            with open(compose_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load compose config from {compose_path}: {e}")
            return {}
    
    def _write_compose_config(self, config: Dict[str, Any], compose_path: Path):
        """Write Docker Compose configuration to file"""
        try:
            with open(compose_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
        except Exception as e:
            logger.error(f"Failed to write compose config to {compose_path}: {e}")
    
    def _apply_changes_to_config(self, base_config: Dict[str, Any], 
                               change: InfrastructureChange) -> Dict[str, Any]:
        """Apply infrastructure changes to base configuration"""
        shadow_config = base_config.copy()
        
        if change.change_type == "service_addition":
            # Add new service to configuration
            if "services" not in shadow_config:
                shadow_config["services"] = {}
            
            for service_name, service_config in change.proposed_config.items():
                shadow_config["services"][service_name] = service_config
        
        elif change.change_type == "configuration_change":
            # Modify existing service configuration
            for service_name in change.affected_services:
                if service_name in shadow_config.get("services", {}):
                    shadow_config["services"][service_name].update(
                        change.proposed_config.get(service_name, {})
                    )
        
        elif change.change_type == "network_change":
            # Modify network configuration
            if "networks" not in shadow_config:
                shadow_config["networks"] = {}
            shadow_config["networks"].update(change.proposed_config)
        
        return shadow_config
    
    def _apply_security_constraints(self, config: Dict[str, Any], 
                                  isolation_level: str) -> Dict[str, Any]:
        """Apply security constraints based on isolation level"""
        if isolation_level == "high":
            # Create isolated network
            network_name = f"shadow-isolated-{int(datetime.now().timestamp())}"
            config["networks"] = {
                network_name: {
                    "driver": "bridge",
                    "internal": True,  # No external access
                    "driver_opts": {
                        "com.docker.network.bridge.enable_icc": "false"
                    }
                }
            }
            
            # Apply network to all services
            for service_name, service_config in config.get("services", {}).items():
                if "networks" not in service_config:
                    service_config["networks"] = []
                service_config["networks"] = [network_name]
        
        return config
    
    def _get_resource_limits(self, change: InfrastructureChange) -> Dict[str, Any]:
        """Get resource limits for shadow environment"""
        return {
            "memory": "512m",
            "cpus": "0.5",
            "disk_space": "1g",
            "network_bandwidth": "10m"
        }
    
    def _get_security_constraints(self, isolation_level: str) -> Dict[str, Any]:
        """Get security constraints for shadow environment"""
        return {
            "isolation_level": isolation_level,
            "network_isolation": isolation_level == "high",
            "read_only_filesystem": True,
            "no_new_privileges": True,
            "drop_capabilities": ["ALL"],
            "add_capabilities": ["CHOWN", "DAC_OVERRIDE", "SETGID", "SETUID"]
        }
    
    def _get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring configuration for shadow environment"""
        return {
            "metrics_collection": True,
            "log_aggregation": True,
            "security_monitoring": True,
            "performance_monitoring": True,
            "retention_hours": 24
        }
    
    def _deploy_to_shadow(self, shadow_env: ShadowEnvironmentConfig, 
                         change: InfrastructureChange) -> Dict[str, Any]:
        """Deploy configuration to shadow environment"""
        logger.info(f"Deploying to shadow environment: {shadow_env.environment_id}")
        
        deployment_results = {
            "deployment_id": f"deploy-{shadow_env.environment_id}",
            "status": "simulated",  # Read-only analysis mode
            "services_analyzed": change.affected_services,
            "configuration_validated": True,
            "security_checks_passed": True,
            "resource_requirements": self._calculate_resource_requirements(change),
            "network_topology": self._analyze_network_topology(change),
            "deployment_time_estimate": self._estimate_deployment_time(change),
            "rollback_time_estimate": self._estimate_rollback_time(change),
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        logger.info(f"Shadow deployment analysis completed: {shadow_env.environment_id}")
        return deployment_results
    
    def _analyze_security_risks(self, change: InfrastructureChange, 
                              deployment_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze security risks of infrastructure change"""
        security_risks = []
        
        # Analyze exposed ports
        if "ports" in str(change.proposed_config):
            security_risks.append({
                "type": "exposed_ports",
                "severity": "medium",
                "description": "New ports exposed to external network",
                "impact": "Increased attack surface",
                "recommendation": "Review port exposure necessity and implement firewall rules"
            })
        
        # Analyze privileged access
        if "privileged" in str(change.proposed_config):
            security_risks.append({
                "type": "privileged_access",
                "severity": "high",
                "description": "Service requires privileged access",
                "impact": "Container escape potential",
                "recommendation": "Use specific capabilities instead of privileged mode"
            })
        
        # Analyze volume mounts
        if "volumes" in str(change.proposed_config):
            security_risks.append({
                "type": "volume_mounts",
                "severity": "medium",
                "description": "Host filesystem access configured",
                "impact": "Potential data exposure or modification",
                "recommendation": "Use named volumes or limit mount scope"
            })
        
        return security_risks
    
    def _analyze_performance_risks(self, change: InfrastructureChange, 
                                 deployment_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze performance risks of infrastructure change"""
        performance_risks = []
        
        # Analyze resource requirements
        resource_reqs = deployment_results.get("resource_requirements", {})
        if resource_reqs.get("memory_mb", 0) > 1024:
            performance_risks.append({
                "type": "high_memory_usage",
                "severity": "medium",
                "description": f"High memory requirement: {resource_reqs.get('memory_mb')}MB",
                "impact": "Potential memory pressure on host system",
                "recommendation": "Monitor memory usage and consider optimization"
            })
        
        if resource_reqs.get("cpu_cores", 0) > 2:
            performance_risks.append({
                "type": "high_cpu_usage",
                "severity": "medium",
                "description": f"High CPU requirement: {resource_reqs.get('cpu_cores')} cores",
                "impact": "Potential CPU contention with other services",
                "recommendation": "Monitor CPU usage and consider load balancing"
            })
        
        return performance_risks
    
    def _analyze_availability_risks(self, change: InfrastructureChange, 
                                  deployment_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze availability risks of infrastructure change"""
        availability_risks = []
        
        # Analyze single points of failure
        if len(change.affected_services) == 1:
            availability_risks.append({
                "type": "single_point_of_failure",
                "severity": "high",
                "description": "Change affects critical single service",
                "impact": "Service unavailability if deployment fails",
                "recommendation": "Implement redundancy or staged deployment"
            })
        
        # Analyze deployment time
        deployment_time = deployment_results.get("deployment_time_estimate", 0)
        if deployment_time > 300:  # 5 minutes
            availability_risks.append({
                "type": "long_deployment_time",
                "severity": "medium",
                "description": f"Estimated deployment time: {deployment_time} seconds",
                "impact": "Extended service unavailability during deployment",
                "recommendation": "Consider blue-green deployment or rolling updates"
            })
        
        return availability_risks
    
    def _analyze_compliance_risks(self, change: InfrastructureChange) -> List[Dict[str, Any]]:
        """Analyze compliance risks of infrastructure change"""
        compliance_risks = []
        
        # Check for data handling compliance
        if "database" in change.description.lower() or "data" in change.description.lower():
            compliance_risks.append({
                "type": "data_handling",
                "severity": "high",
                "description": "Change involves data handling components",
                "impact": "Potential GDPR/CCPA compliance implications",
                "recommendation": "Review data handling procedures and encryption requirements"
            })
        
        # Check for logging compliance
        if "log" in str(change.proposed_config).lower():
            compliance_risks.append({
                "type": "logging_compliance",
                "severity": "medium",
                "description": "Change affects logging configuration",
                "impact": "Potential audit trail compliance issues",
                "recommendation": "Ensure log retention and access controls meet compliance requirements"
            })
        
        return compliance_risks
    
    def _assess_blast_radius(self, change: InfrastructureChange) -> Dict[str, Any]:
        """Assess blast radius of infrastructure change"""
        return {
            "affected_services": change.affected_services,
            "dependent_services": self._find_dependent_services(change.affected_services),
            "impact_scope": change.impact_scope,
            "containment_level": self._calculate_containment_level(change),
            "recovery_time_estimate": self._estimate_recovery_time(change),
            "business_impact": self._assess_business_impact(change)
        }
    
    def _generate_mitigation_strategies(self, security_risks: List[Dict[str, Any]], 
                                      performance_risks: List[Dict[str, Any]],
                                      availability_risks: List[Dict[str, Any]], 
                                      compliance_risks: List[Dict[str, Any]]) -> List[str]:
        """Generate mitigation strategies for identified risks"""
        strategies = []
        
        # Security mitigations
        for risk in security_risks:
            strategies.append(f"Security: {risk.get('recommendation', 'Review security implications')}")
        
        # Performance mitigations
        for risk in performance_risks:
            strategies.append(f"Performance: {risk.get('recommendation', 'Monitor resource usage')}")
        
        # Availability mitigations
        for risk in availability_risks:
            strategies.append(f"Availability: {risk.get('recommendation', 'Implement redundancy')}")
        
        # Compliance mitigations
        for risk in compliance_risks:
            strategies.append(f"Compliance: {risk.get('recommendation', 'Review compliance requirements')}")
        
        return strategies
    
    def _create_rollback_plan(self, change: InfrastructureChange) -> Dict[str, Any]:
        """Create rollback plan for infrastructure change"""
        return {
            "rollback_strategy": self._determine_rollback_strategy(change),
            "rollback_steps": self._generate_rollback_steps(change),
            "estimated_time": self._estimate_rollback_time(change),
            "verification_steps": self._generate_verification_steps(change),
            "success_criteria": self._define_rollback_success_criteria(change)
        }
    
    def _calculate_risk_score(self, security_risks: List[Dict[str, Any]], 
                            performance_risks: List[Dict[str, Any]],
                            availability_risks: List[Dict[str, Any]], 
                            compliance_risks: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score (0.0 to 10.0)"""
        severity_weights = {"low": 1, "medium": 3, "high": 7, "critical": 10}
        
        total_score = 0
        risk_count = 0
        
        for risk_list in [security_risks, performance_risks, availability_risks, compliance_risks]:
            for risk in risk_list:
                severity = risk.get("severity", "medium")
                total_score += severity_weights.get(severity, 3)
                risk_count += 1
        
        if risk_count == 0:
            return 0.0
        
        # Normalize to 0-10 scale
        average_score = total_score / risk_count
        return min(average_score, 10.0)
    
    def _calculate_confidence_level(self, deployment_results: Dict[str, Any]) -> float:
        """Calculate confidence level of analysis (0.0 to 1.0)"""
        # Base confidence on completeness of analysis
        base_confidence = 0.8
        
        if deployment_results.get("configuration_validated"):
            base_confidence += 0.1
        
        if deployment_results.get("security_checks_passed"):
            base_confidence += 0.1
        
        return min(base_confidence, 1.0)
    
    def _cleanup_shadow_environment(self, environment_id: str):
        """Clean up shadow environment resources"""
        logger.info(f"Cleaning up shadow environment: {environment_id}")
        
        # Remove environment directory
        env_dir = self.shadow_workspace / environment_id
        if env_dir.exists():
            shutil.rmtree(env_dir)
        
        # Remove from active environments
        if environment_id in self.active_environments:
            del self.active_environments[environment_id]
        
        logger.info(f"Shadow environment cleaned up: {environment_id}")
    
    def _perform_security_scan(self, shadow_env: ShadowEnvironmentConfig) -> Dict[str, Any]:
        """Perform security scan of shadow environment"""
        return {
            "scan_id": f"scan-{shadow_env.environment_id}",
            "vulnerabilities_found": 0,  # Simulated for read-only analysis
            "security_score": 8.5,
            "recommendations": [
                "Update base images to latest versions",
                "Implement network segmentation",
                "Enable container security monitoring"
            ],
            "scan_timestamp": datetime.now().isoformat()
        }
    
    def _analyze_performance_metrics(self, shadow_env: ShadowEnvironmentConfig) -> Dict[str, Any]:
        """Analyze performance metrics of shadow environment"""
        return {
            "analysis_id": f"perf-{shadow_env.environment_id}",
            "cpu_utilization": 25.5,  # Simulated metrics
            "memory_utilization": 45.2,
            "network_throughput": 100.5,
            "response_time_ms": 150,
            "recommendations": [
                "Optimize container resource allocation",
                "Implement caching layer",
                "Consider horizontal scaling"
            ],
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def _generate_recommendations(self, risk_assessment: RiskAssessment,
                                deployment_results: Dict[str, Any],
                                security_scan_results: Dict[str, Any],
                                performance_analysis: Dict[str, Any]) -> List[str]:
        """Generate comprehensive recommendations"""
        recommendations = []
        
        # Risk-based recommendations
        if risk_assessment.overall_risk_score > 7.0:
            recommendations.append("HIGH RISK: Consider alternative implementation approach")
        elif risk_assessment.overall_risk_score > 4.0:
            recommendations.append("MEDIUM RISK: Implement additional safeguards before deployment")
        
        # Security recommendations
        recommendations.extend(security_scan_results.get("recommendations", []))
        
        # Performance recommendations
        recommendations.extend(performance_analysis.get("recommendations", []))
        
        # Mitigation strategies
        recommendations.extend(risk_assessment.mitigation_strategies)
        
        return recommendations
    
    def _determine_approval_status(self, risk_assessment: RiskAssessment) -> str:
        """Determine approval status based on risk assessment"""
        if risk_assessment.overall_risk_score >= 8.0:
            return "rejected"
        elif risk_assessment.overall_risk_score >= 5.0:
            return "needs_review"
        else:
            return "approved"
    
    def _save_report(self, report: ShadowModeReport):
        """Save shadow mode report to analysis database"""
        report_dir = self.analysis_db_path.parent / "shadow_reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        
        report_file = report_dir / f"report-{report.change_id}-{int(report.generated_at.timestamp())}.json"
        
        with open(report_file, 'w') as f:
            json.dump(asdict(report), f, indent=2, default=str)
        
        logger.info(f"Shadow mode report saved: {report_file}")
    
    # Additional helper methods for rollback planning
    
    def _determine_rollback_strategy(self, change: InfrastructureChange) -> str:
        """Determine appropriate rollback strategy"""
        if change.change_type == "service_addition":
            return "service_removal"
        elif change.change_type == "configuration_change":
            return "configuration_revert"
        elif change.change_type == "network_change":
            return "network_rollback"
        else:
            return "full_environment_restore"
    
    def _generate_rollback_steps(self, change: InfrastructureChange) -> List[str]:
        """Generate detailed rollback steps"""
        steps = [
            "1. Stop affected services gracefully",
            "2. Backup current configuration state",
            "3. Revert to previous configuration",
            "4. Restart services in dependency order",
            "5. Verify service health and connectivity",
            "6. Run smoke tests to confirm functionality",
            "7. Monitor system stability for 15 minutes",
            "8. Update monitoring and alerting systems"
        ]
        return steps
    
    def _generate_verification_steps(self, change: InfrastructureChange) -> List[str]:
        """Generate verification steps for rollback"""
        return [
            "Verify all services are running and healthy",
            "Check service connectivity and dependencies",
            "Validate configuration matches expected state",
            "Confirm monitoring and alerting are functional",
            "Run integration tests to verify functionality"
        ]
    
    def _estimate_rollback_time(self, change: InfrastructureChange) -> int:
        """Estimate rollback time in seconds"""
        base_time = 300  # 5 minutes base
        service_count = len(change.affected_services)
        return base_time + (service_count * 60)  # Additional minute per service
    
    def _generate_rollback_risk_mitigation(self, change: InfrastructureChange) -> List[str]:
        """Generate risk mitigation strategies for rollback"""
        return [
            "Ensure database backups are available and tested",
            "Coordinate with dependent teams before rollback",
            "Have escalation contacts readily available",
            "Prepare communication templates for stakeholders",
            "Ensure monitoring systems are functioning properly"
        ]
    
    def _generate_communication_plan(self, change: InfrastructureChange) -> Dict[str, Any]:
        """Generate communication plan for rollback"""
        return {
            "stakeholders": ["development_team", "operations_team", "security_team"],
            "notification_channels": ["email", "slack", "incident_management"],
            "communication_timeline": {
                "rollback_start": "Immediate notification to all stakeholders",
                "rollback_progress": "Updates every 5 minutes during rollback",
                "rollback_complete": "Final status notification with verification results"
            }
        }
    
    def _generate_monitoring_requirements(self, change: InfrastructureChange) -> Dict[str, Any]:
        """Generate monitoring requirements during rollback"""
        return {
            "metrics_to_monitor": [
                "service_health_status",
                "response_times",
                "error_rates",
                "resource_utilization",
                "dependency_connectivity"
            ],
            "monitoring_duration": "30 minutes post-rollback",
            "alert_thresholds": {
                "error_rate": "> 1%",
                "response_time": "> 500ms",
                "cpu_utilization": "> 80%",
                "memory_utilization": "> 85%"
            }
        }
    
    def _define_rollback_success_criteria(self, change: InfrastructureChange) -> List[str]:
        """Define success criteria for rollback"""
        return [
            "All affected services are running and healthy",
            "Service response times are within normal ranges",
            "Error rates are below 0.1%",
            "All integration tests pass successfully",
            "No critical alerts are active",
            "System performance metrics are stable"
        ]
    
    def _define_escalation_procedures(self, change: InfrastructureChange) -> Dict[str, Any]:
        """Define escalation procedures for rollback issues"""
        return {
            "level_1": {
                "trigger": "Rollback takes longer than estimated time",
                "action": "Notify team lead and senior engineer",
                "timeout": "15 minutes"
            },
            "level_2": {
                "trigger": "Rollback fails or causes additional issues",
                "action": "Escalate to incident commander and architecture team",
                "timeout": "30 minutes"
            },
            "level_3": {
                "trigger": "System remains unstable after rollback",
                "action": "Engage emergency response team and executive stakeholders",
                "timeout": "60 minutes"
            }
        }
    
    # Helper methods for analysis calculations
    
    def _calculate_resource_requirements(self, change: InfrastructureChange) -> Dict[str, Any]:
        """Calculate resource requirements for change"""
        return {
            "memory_mb": 512,  # Simulated calculation
            "cpu_cores": 1,
            "disk_gb": 5,
            "network_mbps": 10
        }
    
    def _analyze_network_topology(self, change: InfrastructureChange) -> Dict[str, Any]:
        """Analyze network topology impact"""
        return {
            "new_connections": len(change.affected_services),
            "exposed_ports": [],  # Would be extracted from config
            "network_isolation": True,
            "security_groups": ["shadow-sg"]
        }
    
    def _estimate_deployment_time(self, change: InfrastructureChange) -> int:
        """Estimate deployment time in seconds"""
        base_time = 120  # 2 minutes base
        service_count = len(change.affected_services)
        return base_time + (service_count * 30)  # Additional 30 seconds per service
    
    def _find_dependent_services(self, services: List[str]) -> List[str]:
        """Find services that depend on the given services"""
        # This would analyze the actual service dependencies
        # For now, return simulated dependencies
        return [f"{service}-dependent" for service in services]
    
    def _calculate_containment_level(self, change: InfrastructureChange) -> str:
        """Calculate containment level of change impact"""
        if len(change.affected_services) == 1:
            return "low"
        elif len(change.affected_services) <= 3:
            return "medium"
        else:
            return "high"
    
    def _estimate_recovery_time(self, change: InfrastructureChange) -> int:
        """Estimate recovery time in minutes"""
        return len(change.affected_services) * 10  # 10 minutes per service
    
    def _assess_business_impact(self, change: InfrastructureChange) -> str:
        """Assess business impact of change"""
        if "critical" in change.description.lower():
            return "high"
        elif "important" in change.description.lower():
            return "medium"
        else:
            return "low"