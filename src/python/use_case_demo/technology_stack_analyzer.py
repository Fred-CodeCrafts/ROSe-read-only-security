"""
Technology Stack Compliance Analysis

This module implements comprehensive technology stack validation, cost analysis,
deployment readiness assessment, and technology recommendation capabilities
for the cybersecurity platform.
"""

import json
import yaml
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import logging
import subprocess
import sys
import os

# Import platform components
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..'))

@dataclass
class TechnologyComponent:
    """Represents a technology component in the stack."""
    name: str
    version: str
    category: str  # database, ai_framework, security_tool, etc.
    license: str
    security_rating: str  # HIGH, MEDIUM, LOW
    cost_tier: str  # FREE, PAID, ENTERPRISE
    deployment_complexity: str  # SIMPLE, MODERATE, COMPLEX
    dependencies: List[str]
    vulnerabilities: List[str]
    alternatives: List[str]

@dataclass
class ComplianceResult:
    """Represents compliance analysis results."""
    component: str
    compliant: bool
    issues: List[str]
    recommendations: List[str]
    risk_score: float
    cost_impact: str

@dataclass
class DeploymentReadiness:
    """Represents deployment readiness assessment."""
    overall_score: float
    security_score: float
    performance_score: float
    cost_score: float
    readiness_level: str  # READY, NEEDS_ATTENTION, NOT_READY
    blockers: List[str]
    recommendations: List[str]

class TechnologyStackAnalyzer:
    """
    Comprehensive technology stack compliance and analysis engine.
    
    Provides security assessment, cost analysis, deployment readiness,
    and technology recommendations for the cybersecurity platform.
    """
    
    def __init__(self, project_root: str = None):
        """Initialize the technology stack analyzer."""
        self.project_root = Path(project_root) if project_root else Path.cwd()
        self.logger = logging.getLogger(__name__)
        
        # Define technology stack components
        self.stack_components = self._initialize_stack_components()
        
        # Define compliance rules
        self.compliance_rules = self._initialize_compliance_rules()
        
        # Define cost thresholds
        self.cost_thresholds = {
            'free_tier_limit': 1000.0,  # USD per month
            'warning_threshold': 800.0,
            'optimization_threshold': 500.0
        }
    
    def _initialize_stack_components(self) -> Dict[str, TechnologyComponent]:
        """Initialize the technology stack components."""
        return {
            'ollama': TechnologyComponent(
                name='Ollama',
                version='latest',
                category='ai_framework',
                license='MIT',
                security_rating='HIGH',
                cost_tier='FREE',
                deployment_complexity='SIMPLE',
                dependencies=['docker'],
                vulnerabilities=[],
                alternatives=['OpenAI API', 'Anthropic Claude', 'Hugging Face']
            ),
            'duckdb': TechnologyComponent(
                name='DuckDB',
                version='latest',
                category='database',
                license='MIT',
                security_rating='HIGH',
                cost_tier='FREE',
                deployment_complexity='SIMPLE',
                dependencies=[],
                vulnerabilities=[],
                alternatives=['SQLite', 'PostgreSQL', 'ClickHouse']
            ),
            'chromadb': TechnologyComponent(
                name='ChromaDB',
                version='latest',
                category='vector_database',
                license='Apache-2.0',
                security_rating='MEDIUM',
                cost_tier='FREE',
                deployment_complexity='MODERATE',
                dependencies=['sqlite3'],
                vulnerabilities=[],
                alternatives=['Pinecone', 'Weaviate', 'Qdrant']
            ),
            'minio': TechnologyComponent(
                name='MinIO',
                version='latest',
                category='object_storage',
                license='AGPL-3.0',
                security_rating='HIGH',
                cost_tier='FREE',
                deployment_complexity='MODERATE',
                dependencies=['docker'],
                vulnerabilities=[],
                alternatives=['AWS S3', 'Google Cloud Storage', 'Azure Blob']
            ),
            'wazuh': TechnologyComponent(
                name='Wazuh',
                version='4.7',
                category='security_tool',
                license='GPL-2.0',
                security_rating='HIGH',
                cost_tier='FREE',
                deployment_complexity='COMPLEX',
                dependencies=['elasticsearch', 'docker'],
                vulnerabilities=[],
                alternatives=['Splunk', 'ELK Stack', 'Sumo Logic']
            ),
            'falco': TechnologyComponent(
                name='Falco',
                version='latest',
                category='security_tool',
                license='Apache-2.0',
                security_rating='HIGH',
                cost_tier='FREE',
                deployment_complexity='MODERATE',
                dependencies=['kernel-headers'],
                vulnerabilities=[],
                alternatives=['Sysdig', 'Datadog Security', 'Aqua Security']
            ),
            'prometheus': TechnologyComponent(
                name='Prometheus',
                version='latest',
                category='monitoring',
                license='Apache-2.0',
                security_rating='HIGH',
                cost_tier='FREE',
                deployment_complexity='MODERATE',
                dependencies=['docker'],
                vulnerabilities=[],
                alternatives=['Grafana Cloud', 'DataDog', 'New Relic']
            ),
            'grafana': TechnologyComponent(
                name='Grafana',
                version='latest',
                category='visualization',
                license='AGPL-3.0',
                security_rating='HIGH',
                cost_tier='FREE',
                deployment_complexity='SIMPLE',
                dependencies=['prometheus'],
                vulnerabilities=[],
                alternatives=['Kibana', 'Tableau', 'Power BI']
            )
        }
    
    def _initialize_compliance_rules(self) -> Dict[str, Any]:
        """Initialize compliance rules for technology stack validation."""
        return {
            'security_requirements': {
                'min_security_rating': 'MEDIUM',
                'max_vulnerabilities': 5,
                'required_licenses': ['MIT', 'Apache-2.0', 'BSD', 'GPL-2.0', 'AGPL-3.0'],
                'forbidden_licenses': ['SSPL', 'Commons Clause']
            },
            'cost_requirements': {
                'max_monthly_cost': 1000.0,
                'preferred_cost_tier': 'FREE',
                'cost_optimization_target': 500.0
            },
            'deployment_requirements': {
                'max_complexity': 'COMPLEX',
                'container_support': True,
                'cloud_native': True,
                'self_hosted': True
            },
            'performance_requirements': {
                'max_startup_time': 300,  # seconds
                'min_availability': 99.0,  # percentage
                'max_resource_usage': 80.0  # percentage
            }
        }
    
    def analyze_technology_stack(self) -> Dict[str, Any]:
        """
        Perform comprehensive technology stack analysis.
        
        Returns:
            Dict containing complete analysis results
        """
        try:
            # Analyze each component
            component_analyses = {}
            for name, component in self.stack_components.items():
                component_analyses[name] = self._analyze_component(component)
            
            # Perform overall compliance analysis
            compliance_results = self._analyze_compliance(component_analyses)
            
            # Calculate cost analysis
            cost_analysis = self._analyze_costs(component_analyses)
            
            # Assess deployment readiness
            deployment_readiness = self._assess_deployment_readiness(component_analyses)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                component_analyses, compliance_results, cost_analysis, deployment_readiness
            )
            
            return {
                'timestamp': datetime.now().isoformat(),
                'component_analyses': component_analyses,
                'compliance_results': compliance_results,
                'cost_analysis': cost_analysis,
                'deployment_readiness': asdict(deployment_readiness),
                'recommendations': recommendations,
                'overall_score': self._calculate_overall_score(
                    compliance_results, cost_analysis, deployment_readiness
                )
            }
            
        except Exception as e:
            self.logger.error(f"Error in technology stack analysis: {e}")
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'status': 'failed'
            }
    
    def _analyze_component(self, component: TechnologyComponent) -> Dict[str, Any]:
        """Analyze a single technology component."""
        analysis = {
            'component': asdict(component),
            'security_assessment': self._assess_component_security(component),
            'cost_assessment': self._assess_component_cost(component),
            'deployment_assessment': self._assess_component_deployment(component),
            'compliance_status': self._check_component_compliance(component)
        }
        
        return analysis
    
    def _assess_component_security(self, component: TechnologyComponent) -> Dict[str, Any]:
        """Assess security aspects of a component."""
        security_score = 100.0
        issues = []
        
        # Check security rating
        if component.security_rating == 'LOW':
            security_score -= 30
            issues.append(f"Low security rating for {component.name}")
        elif component.security_rating == 'MEDIUM':
            security_score -= 10
        
        # Check vulnerabilities
        vuln_count = len(component.vulnerabilities)
        if vuln_count > 0:
            security_score -= min(vuln_count * 10, 50)
            issues.append(f"{vuln_count} known vulnerabilities in {component.name}")
        
        # Check license security implications
        if component.license not in self.compliance_rules['security_requirements']['required_licenses']:
            security_score -= 20
            issues.append(f"License {component.license} may have security implications")
        
        return {
            'security_score': max(security_score, 0),
            'issues': issues,
            'vulnerabilities': component.vulnerabilities,
            'security_rating': component.security_rating
        }
    
    def _assess_component_cost(self, component: TechnologyComponent) -> Dict[str, Any]:
        """Assess cost implications of a component."""
        base_cost = 0.0
        cost_factors = []
        
        # Base cost by tier
        if component.cost_tier == 'FREE':
            base_cost = 0.0
        elif component.cost_tier == 'PAID':
            base_cost = 100.0  # Estimated monthly cost
            cost_factors.append("Paid tier component")
        elif component.cost_tier == 'ENTERPRISE':
            base_cost = 500.0
            cost_factors.append("Enterprise tier component")
        
        # Deployment complexity cost
        if component.deployment_complexity == 'COMPLEX':
            base_cost += 50.0  # Operational overhead
            cost_factors.append("Complex deployment increases operational costs")
        
        # Dependency costs
        dependency_cost = len(component.dependencies) * 10.0
        base_cost += dependency_cost
        if dependency_cost > 0:
            cost_factors.append(f"Dependencies add ${dependency_cost:.2f} operational cost")
        
        return {
            'estimated_monthly_cost': base_cost,
            'cost_tier': component.cost_tier,
            'cost_factors': cost_factors,
            'free_tier_compliant': base_cost == 0.0
        }
    
    def _assess_component_deployment(self, component: TechnologyComponent) -> Dict[str, Any]:
        """Assess deployment characteristics of a component."""
        deployment_score = 100.0
        deployment_issues = []
        
        # Complexity penalty
        if component.deployment_complexity == 'COMPLEX':
            deployment_score -= 30
            deployment_issues.append(f"Complex deployment for {component.name}")
        elif component.deployment_complexity == 'MODERATE':
            deployment_score -= 10
        
        # Dependency complexity
        dep_count = len(component.dependencies)
        if dep_count > 3:
            deployment_score -= 20
            deployment_issues.append(f"High dependency count ({dep_count}) for {component.name}")
        elif dep_count > 1:
            deployment_score -= 5
        
        return {
            'deployment_score': max(deployment_score, 0),
            'complexity': component.deployment_complexity,
            'dependency_count': dep_count,
            'issues': deployment_issues
        }
    
    def _check_component_compliance(self, component: TechnologyComponent) -> ComplianceResult:
        """Check component compliance against rules."""
        issues = []
        recommendations = []
        risk_score = 0.0
        
        # Security compliance
        if component.security_rating == 'LOW':
            issues.append("Security rating below minimum requirement")
            risk_score += 30
            recommendations.append(f"Consider upgrading {component.name} or using alternatives")
        
        # License compliance
        if component.license in self.compliance_rules['security_requirements']['forbidden_licenses']:
            issues.append(f"License {component.license} is not permitted")
            risk_score += 50
            recommendations.append(f"Replace {component.name} with alternative having compatible license")
        
        # Cost compliance
        if component.cost_tier != 'FREE':
            issues.append("Component not in free tier")
            risk_score += 10
            recommendations.append(f"Evaluate free alternatives to {component.name}")
        
        # Vulnerability compliance
        vuln_count = len(component.vulnerabilities)
        if vuln_count > self.compliance_rules['security_requirements']['max_vulnerabilities']:
            issues.append(f"Too many vulnerabilities ({vuln_count})")
            risk_score += 20
            recommendations.append(f"Update {component.name} to latest secure version")
        
        compliant = len(issues) == 0
        cost_impact = "LOW" if component.cost_tier == 'FREE' else "MEDIUM" if component.cost_tier == 'PAID' else "HIGH"
        
        return ComplianceResult(
            component=component.name,
            compliant=compliant,
            issues=issues,
            recommendations=recommendations,
            risk_score=risk_score,
            cost_impact=cost_impact
        )
    
    def _analyze_compliance(self, component_analyses: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze overall compliance across all components."""
        total_components = len(component_analyses)
        compliant_components = 0
        total_risk_score = 0.0
        all_issues = []
        all_recommendations = []
        
        for name, analysis in component_analyses.items():
            compliance = analysis['compliance_status']
            if compliance.compliant:
                compliant_components += 1
            
            total_risk_score += compliance.risk_score
            all_issues.extend(compliance.issues)
            all_recommendations.extend(compliance.recommendations)
        
        compliance_percentage = (compliant_components / total_components) * 100
        average_risk_score = total_risk_score / total_components
        
        return {
            'compliance_percentage': compliance_percentage,
            'compliant_components': compliant_components,
            'total_components': total_components,
            'average_risk_score': average_risk_score,
            'overall_compliant': compliance_percentage >= 80.0,
            'issues': all_issues,
            'recommendations': all_recommendations
        }
    
    def _analyze_costs(self, component_analyses: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze cost implications across all components."""
        total_cost = 0.0
        free_tier_components = 0
        cost_factors = []
        
        for name, analysis in component_analyses.items():
            cost_assessment = analysis['cost_assessment']
            total_cost += cost_assessment['estimated_monthly_cost']
            
            if cost_assessment['free_tier_compliant']:
                free_tier_components += 1
            
            cost_factors.extend(cost_assessment['cost_factors'])
        
        free_tier_percentage = (free_tier_components / len(component_analyses)) * 100
        
        return {
            'total_estimated_monthly_cost': total_cost,
            'free_tier_percentage': free_tier_percentage,
            'free_tier_compliant': total_cost == 0.0,  # True free-tier means $0 cost
            'cost_optimization_needed': total_cost > self.cost_thresholds['optimization_threshold'],
            'cost_warning': total_cost > self.cost_thresholds['warning_threshold'],
            'cost_factors': cost_factors,
            'cost_breakdown': {
                name: analysis['cost_assessment']['estimated_monthly_cost']
                for name, analysis in component_analyses.items()
            }
        }
    
    def _assess_deployment_readiness(self, component_analyses: Dict[str, Any]) -> DeploymentReadiness:
        """Assess overall deployment readiness."""
        security_scores = []
        deployment_scores = []
        cost_scores = []
        blockers = []
        recommendations = []
        
        for name, analysis in component_analyses.items():
            # Security score
            security_scores.append(analysis['security_assessment']['security_score'])
            
            # Deployment score
            deployment_scores.append(analysis['deployment_assessment']['deployment_score'])
            
            # Cost score (inverse of cost - higher cost = lower score)
            cost = analysis['cost_assessment']['estimated_monthly_cost']
            cost_score = max(100 - (cost / 10), 0)  # Scale cost to 0-100
            cost_scores.append(cost_score)
            
            # Collect blockers
            if not analysis['compliance_status'].compliant:
                blockers.extend(analysis['compliance_status'].issues)
            
            # Collect recommendations
            recommendations.extend(analysis['compliance_status'].recommendations)
        
        # Calculate average scores
        security_score = sum(security_scores) / len(security_scores)
        performance_score = sum(deployment_scores) / len(deployment_scores)
        cost_score = sum(cost_scores) / len(cost_scores)
        overall_score = (security_score + performance_score + cost_score) / 3
        
        # Determine readiness level
        if overall_score >= 80 and len(blockers) == 0:
            readiness_level = "READY"
        elif overall_score >= 60:
            readiness_level = "NEEDS_ATTENTION"
        else:
            readiness_level = "NOT_READY"
        
        return DeploymentReadiness(
            overall_score=overall_score,
            security_score=security_score,
            performance_score=performance_score,
            cost_score=cost_score,
            readiness_level=readiness_level,
            blockers=list(set(blockers)),  # Remove duplicates
            recommendations=list(set(recommendations))  # Remove duplicates
        )
    
    def _generate_recommendations(self, component_analyses: Dict[str, Any], 
                                compliance_results: Dict[str, Any],
                                cost_analysis: Dict[str, Any],
                                deployment_readiness: DeploymentReadiness) -> List[Dict[str, Any]]:
        """Generate technology recommendations based on analysis."""
        recommendations = []
        
        # Security recommendations
        if compliance_results['average_risk_score'] > 20:
            recommendations.append({
                'category': 'security',
                'priority': 'HIGH',
                'title': 'Address Security Risks',
                'description': 'Multiple components have security concerns that need attention',
                'actions': [
                    'Review components with LOW security ratings',
                    'Update components with known vulnerabilities',
                    'Consider security-focused alternatives'
                ]
            })
        
        # Cost optimization recommendations
        if cost_analysis['cost_optimization_needed']:
            recommendations.append({
                'category': 'cost',
                'priority': 'MEDIUM',
                'title': 'Optimize Costs',
                'description': f"Current estimated cost ${cost_analysis['total_estimated_monthly_cost']:.2f} exceeds optimization target",
                'actions': [
                    'Evaluate free alternatives for paid components',
                    'Optimize resource usage and deployment complexity',
                    'Consider cloud-native solutions for better cost efficiency'
                ]
            })
        
        # Deployment recommendations
        if deployment_readiness.readiness_level != "READY":
            recommendations.append({
                'category': 'deployment',
                'priority': 'HIGH' if deployment_readiness.readiness_level == "NOT_READY" else 'MEDIUM',
                'title': 'Improve Deployment Readiness',
                'description': f"Deployment readiness is {deployment_readiness.readiness_level}",
                'actions': [
                    'Address deployment blockers',
                    'Simplify complex deployment processes',
                    'Improve documentation and automation'
                ]
            })
        
        # Technology alternatives
        for name, analysis in component_analyses.items():
            component = analysis['component']
            if not analysis['compliance_status'].compliant:
                alternatives = component['alternatives'][:3]  # Top 3 alternatives
                recommendations.append({
                    'category': 'alternatives',
                    'priority': 'MEDIUM',
                    'title': f'Consider Alternatives to {component["name"]}',
                    'description': f'{component["name"]} has compliance issues',
                    'actions': [f'Evaluate {alt}' for alt in alternatives]
                })
        
        return recommendations
    
    def _calculate_overall_score(self, compliance_results: Dict[str, Any],
                               cost_analysis: Dict[str, Any],
                               deployment_readiness: DeploymentReadiness) -> float:
        """Calculate overall technology stack score."""
        # Weight different aspects
        compliance_weight = 0.4
        cost_weight = 0.3
        deployment_weight = 0.3
        
        # Compliance score (based on compliance percentage)
        compliance_score = compliance_results['compliance_percentage']
        
        # Cost score (inverse relationship with cost)
        max_cost = self.cost_thresholds['free_tier_limit']
        actual_cost = cost_analysis['total_estimated_monthly_cost']
        cost_score = max(100 - (actual_cost / max_cost * 100), 0)
        
        # Deployment score
        deployment_score = deployment_readiness.overall_score
        
        # Calculate weighted average
        overall_score = (
            compliance_score * compliance_weight +
            cost_score * cost_weight +
            deployment_score * deployment_weight
        )
        
        return round(overall_score, 2)
    
    def generate_compliance_report(self) -> str:
        """Generate a comprehensive compliance report."""
        analysis = self.analyze_technology_stack()
        
        if 'error' in analysis:
            return f"Error generating compliance report: {analysis['error']}"
        
        report = []
        report.append("# Technology Stack Compliance Report")
        report.append(f"Generated: {analysis['timestamp']}")
        report.append(f"Overall Score: {analysis['overall_score']}/100")
        report.append("")
        
        # Compliance summary
        compliance = analysis['compliance_results']
        report.append("## Compliance Summary")
        report.append(f"- Compliant Components: {compliance['compliant_components']}/{compliance['total_components']}")
        report.append(f"- Compliance Percentage: {compliance['compliance_percentage']:.1f}%")
        report.append(f"- Average Risk Score: {compliance['average_risk_score']:.1f}")
        report.append(f"- Overall Compliant: {'Yes' if compliance['overall_compliant'] else 'No'}")
        report.append("")
        
        # Cost analysis
        cost = analysis['cost_analysis']
        report.append("## Cost Analysis")
        report.append(f"- Estimated Monthly Cost: ${cost['total_estimated_monthly_cost']:.2f}")
        report.append(f"- Free Tier Percentage: {cost['free_tier_percentage']:.1f}%")
        report.append(f"- Free Tier Compliant: {'Yes' if cost['free_tier_compliant'] else 'No'}")
        report.append("")
        
        # Deployment readiness
        deployment = analysis['deployment_readiness']
        report.append("## Deployment Readiness")
        report.append(f"- Readiness Level: {deployment['readiness_level']}")
        report.append(f"- Security Score: {deployment['security_score']:.1f}/100")
        report.append(f"- Performance Score: {deployment['performance_score']:.1f}/100")
        report.append(f"- Cost Score: {deployment['cost_score']:.1f}/100")
        report.append("")
        
        # Recommendations
        if analysis['recommendations']:
            report.append("## Recommendations")
            for i, rec in enumerate(analysis['recommendations'], 1):
                report.append(f"{i}. **{rec['title']}** ({rec['priority']} Priority)")
                report.append(f"   - {rec['description']}")
                for action in rec['actions']:
                    report.append(f"   - {action}")
                report.append("")
        
        return "\n".join(report)
    
    def save_analysis_results(self, output_dir: str = None) -> str:
        """Save analysis results to JSON file."""
        if output_dir is None:
            output_dir = self.project_root / "data" / "analysis"
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        analysis = self.analyze_technology_stack()
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"technology_stack_analysis_{timestamp}.json"
        filepath = output_path / filename
        
        with open(filepath, 'w') as f:
            json.dump(analysis, f, indent=2, default=str)
        
        return str(filepath)


def main():
    """Main function for standalone execution."""
    analyzer = TechnologyStackAnalyzer()
    
    print("Technology Stack Compliance Analysis")
    print("=" * 50)
    
    # Generate and display report
    report = analyzer.generate_compliance_report()
    print(report)
    
    # Save detailed analysis
    filepath = analyzer.save_analysis_results()
    print(f"\nDetailed analysis saved to: {filepath}")


if __name__ == "__main__":
    main()