"""
Governance Workflow Documentation Validator

Validates governance workflow documentation and ensures compliance with
organizational policies and security requirements.
"""

import os
import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class GovernanceViolation:
    """Represents a governance policy violation"""
    violation_id: str
    policy_name: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    remediation_steps: List[str] = field(default_factory=list)
    compliance_framework: Optional[str] = None  # 'SOC2', 'ISO27001', 'NIST', etc.


@dataclass
class PolicyComplianceResult:
    """Result of policy compliance check"""
    policy_name: str
    compliance_status: str  # 'compliant', 'non_compliant', 'partial', 'not_applicable'
    compliance_score: float  # 0.0 to 1.0
    violations: List[GovernanceViolation] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class GovernanceValidationReport:
    """Comprehensive governance validation report"""
    validation_id: str
    timestamp: datetime
    target_path: str
    policy_compliance_results: List[PolicyComplianceResult]
    overall_compliance_score: float
    critical_violations: List[GovernanceViolation]
    recommendations: List[str]
    compliance_frameworks: List[str]
    summary: str


class GovernanceValidator:
    """
    Governance Workflow Documentation Validator
    
    Validates governance workflows, policies, and compliance documentation
    against organizational and regulatory requirements.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Define governance policies to check
        self.governance_policies = {
            'data_classification': {
                'name': 'Data Classification Policy',
                'required_files': ['data_classification.md', 'DATA_CLASSIFICATION.md'],
                'required_sections': ['Classification Levels', 'Handling Requirements', 'Access Controls'],
                'severity': 'high',
                'frameworks': ['SOC2', 'ISO27001']
            },
            'access_control': {
                'name': 'Access Control Policy',
                'required_files': ['access_control.md', 'ACCESS_CONTROL.md'],
                'required_sections': ['Authentication', 'Authorization', 'Least Privilege'],
                'severity': 'critical',
                'frameworks': ['SOC2', 'ISO27001', 'NIST']
            },
            'incident_response': {
                'name': 'Incident Response Policy',
                'required_files': ['incident_response.md', 'INCIDENT_RESPONSE.md', 'SECURITY.md'],
                'required_sections': ['Response Team', 'Escalation Procedures', 'Communication Plan'],
                'severity': 'high',
                'frameworks': ['SOC2', 'ISO27001', 'NIST']
            },
            'change_management': {
                'name': 'Change Management Policy',
                'required_files': ['change_management.md', 'CHANGE_MANAGEMENT.md'],
                'required_sections': ['Change Process', 'Approval Workflow', 'Rollback Procedures'],
                'severity': 'medium',
                'frameworks': ['SOC2', 'ITIL']
            },
            'backup_recovery': {
                'name': 'Backup and Recovery Policy',
                'required_files': ['backup_recovery.md', 'BACKUP_RECOVERY.md'],
                'required_sections': ['Backup Schedule', 'Recovery Procedures', 'Testing Requirements'],
                'severity': 'high',
                'frameworks': ['SOC2', 'ISO27001']
            },
            'vendor_management': {
                'name': 'Vendor Management Policy',
                'required_files': ['vendor_management.md', 'VENDOR_MANAGEMENT.md'],
                'required_sections': ['Vendor Assessment', 'Contract Requirements', 'Monitoring'],
                'severity': 'medium',
                'frameworks': ['SOC2']
            }
        }
        
        # Compliance framework requirements
        self.framework_requirements = {
            'SOC2': {
                'required_policies': ['access_control', 'data_classification', 'incident_response', 'backup_recovery'],
                'documentation_standards': ['policy_owner', 'review_date', 'approval_date']
            },
            'ISO27001': {
                'required_policies': ['access_control', 'data_classification', 'incident_response', 'backup_recovery'],
                'documentation_standards': ['policy_owner', 'review_date', 'approval_date', 'risk_assessment']
            },
            'NIST': {
                'required_policies': ['access_control', 'incident_response'],
                'documentation_standards': ['policy_owner', 'implementation_guidance']
            }
        }
    
    def validate_governance_workflows(self, target_path: str, 
                                    compliance_frameworks: List[str] = None) -> GovernanceValidationReport:
        """
        Validate governance workflow documentation
        
        Args:
            target_path: Path to validate
            compliance_frameworks: List of frameworks to validate against (SOC2, ISO27001, NIST)
            
        Returns:
            GovernanceValidationReport with validation results
        """
        self.logger.info(f"Starting governance validation for {target_path}")
        
        validation_id = f"gov_validation_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        target_path_obj = Path(target_path)
        
        if compliance_frameworks is None:
            compliance_frameworks = ['SOC2']  # Default framework
        
        # Validate each governance policy
        policy_compliance_results = []
        all_violations = []
        
        for policy_id, policy_config in self.governance_policies.items():
            result = self._validate_policy_compliance(target_path_obj, policy_id, policy_config)
            policy_compliance_results.append(result)
            all_violations.extend(result.violations)
        
        # Validate framework-specific requirements
        framework_results = []
        for framework in compliance_frameworks:
            if framework in self.framework_requirements:
                framework_result = self._validate_framework_compliance(
                    target_path_obj, framework, policy_compliance_results
                )
                framework_results.append(framework_result)
                all_violations.extend(framework_result.violations)
        
        # Calculate overall compliance score
        overall_score = self._calculate_overall_compliance_score(policy_compliance_results)
        
        # Identify critical violations
        critical_violations = [v for v in all_violations if v.severity == 'critical']
        
        # Generate recommendations
        recommendations = self._generate_governance_recommendations(
            policy_compliance_results, critical_violations, compliance_frameworks
        )
        
        # Generate summary
        summary = self._generate_governance_summary(
            policy_compliance_results, overall_score, critical_violations
        )
        
        # Combine framework results with policy results
        all_results = policy_compliance_results + framework_results
        
        report = GovernanceValidationReport(
            validation_id=validation_id,
            timestamp=datetime.now(),
            target_path=target_path,
            policy_compliance_results=all_results,
            overall_compliance_score=overall_score,
            critical_violations=critical_violations,
            recommendations=recommendations,
            compliance_frameworks=compliance_frameworks,
            summary=summary
        )
        
        self.logger.info(f"Governance validation completed: {overall_score:.1%} compliance")
        return report
    
    def _validate_policy_compliance(self, target_path: Path, policy_id: str, 
                                  policy_config: Dict[str, Any]) -> PolicyComplianceResult:
        """Validate compliance with a specific governance policy"""
        violations = []
        recommendations = []
        
        # Check for required files
        required_files = policy_config.get('required_files', [])
        policy_file_found = None
        
        for file_name in required_files:
            file_path = target_path / file_name
            if file_path.exists():
                policy_file_found = file_path
                break
        
        if not policy_file_found:
            violations.append(GovernanceViolation(
                violation_id=f"{policy_id}_missing_file",
                policy_name=policy_config['name'],
                severity=policy_config.get('severity', 'medium'),
                description=f"Missing required policy file. Expected one of: {', '.join(required_files)}",
                remediation_steps=[f"Create policy file: {required_files[0]}"],
                compliance_framework=', '.join(policy_config.get('frameworks', []))
            ))
            
            compliance_status = 'non_compliant'
            compliance_score = 0.0
        else:
            # Validate file content
            try:
                content = policy_file_found.read_text(encoding='utf-8', errors='ignore')
                content_violations = self._validate_policy_content(
                    policy_file_found, content, policy_id, policy_config
                )
                violations.extend(content_violations)
                
                # Calculate compliance based on violations
                required_sections = policy_config.get('required_sections', [])
                if required_sections:
                    missing_sections = len([v for v in content_violations if 'missing_section' in v.violation_id])
                    section_compliance = max(0.0, 1.0 - (missing_sections / len(required_sections)))
                else:
                    section_compliance = 1.0
                
                # Overall file compliance
                if len(content_violations) == 0:
                    compliance_status = 'compliant'
                    compliance_score = 1.0
                elif section_compliance >= 0.7:
                    compliance_status = 'partial'
                    compliance_score = section_compliance
                else:
                    compliance_status = 'non_compliant'
                    compliance_score = section_compliance
                    
            except Exception as e:
                violations.append(GovernanceViolation(
                    violation_id=f"{policy_id}_unreadable",
                    policy_name=policy_config['name'],
                    severity='medium',
                    description=f"Cannot read policy file: {e}",
                    file_path=str(policy_file_found),
                    remediation_steps=["Fix file encoding or permissions"]
                ))
                compliance_status = 'non_compliant'
                compliance_score = 0.0
        
        # Generate recommendations
        if violations:
            recommendations.extend([f"Address violation: {v.description}" for v in violations[:3]])
        
        return PolicyComplianceResult(
            policy_name=policy_config['name'],
            compliance_status=compliance_status,
            compliance_score=compliance_score,
            violations=violations,
            recommendations=recommendations
        )
    
    def _validate_policy_content(self, file_path: Path, content: str, 
                               policy_id: str, policy_config: Dict[str, Any]) -> List[GovernanceViolation]:
        """Validate the content of a policy file"""
        violations = []
        
        # Check for required sections
        required_sections = policy_config.get('required_sections', [])
        for section in required_sections:
            if not self._has_section(content, section):
                violations.append(GovernanceViolation(
                    violation_id=f"{policy_id}_missing_section_{section.lower().replace(' ', '_')}",
                    policy_name=policy_config['name'],
                    severity='medium',
                    description=f"Missing required section: {section}",
                    file_path=str(file_path),
                    remediation_steps=[f"Add '{section}' section to policy document"],
                    compliance_framework=', '.join(policy_config.get('frameworks', []))
                ))
        
        # Check for policy metadata
        metadata_checks = {
            'policy_owner': r'(?i)(policy\s+owner|owner|responsible\s+party):\s*\S+',
            'review_date': r'(?i)(review\s+date|last\s+reviewed|reviewed\s+on):\s*\d{4}-\d{2}-\d{2}',
            'approval_date': r'(?i)(approval\s+date|approved\s+on|effective\s+date):\s*\d{4}-\d{2}-\d{2}',
            'version': r'(?i)(version|v\.):\s*\d+\.\d+'
        }
        
        for metadata_type, pattern in metadata_checks.items():
            if not re.search(pattern, content):
                violations.append(GovernanceViolation(
                    violation_id=f"{policy_id}_missing_{metadata_type}",
                    policy_name=policy_config['name'],
                    severity='low',
                    description=f"Missing policy metadata: {metadata_type.replace('_', ' ')}",
                    file_path=str(file_path),
                    remediation_steps=[f"Add {metadata_type.replace('_', ' ')} to policy document"]
                ))
        
        # Check for minimum content length
        if len(content.strip()) < 500:
            violations.append(GovernanceViolation(
                violation_id=f"{policy_id}_insufficient_content",
                policy_name=policy_config['name'],
                severity='medium',
                description="Policy document has insufficient content (less than 500 characters)",
                file_path=str(file_path),
                remediation_steps=["Expand policy document with detailed procedures and requirements"]
            ))
        
        # Check for specific policy requirements based on policy type
        if policy_id == 'access_control':
            violations.extend(self._validate_access_control_policy(file_path, content, policy_config))
        elif policy_id == 'incident_response':
            violations.extend(self._validate_incident_response_policy(file_path, content, policy_config))
        elif policy_id == 'data_classification':
            violations.extend(self._validate_data_classification_policy(file_path, content, policy_config))
        
        return violations
    
    def _validate_access_control_policy(self, file_path: Path, content: str, 
                                      policy_config: Dict[str, Any]) -> List[GovernanceViolation]:
        """Validate access control policy specific requirements"""
        violations = []
        
        # Check for authentication methods
        auth_methods = ['multi-factor', 'mfa', '2fa', 'two-factor', 'authentication']
        if not any(method in content.lower() for method in auth_methods):
            violations.append(GovernanceViolation(
                violation_id="access_control_missing_mfa",
                policy_name=policy_config['name'],
                severity='high',
                description="Access control policy should specify multi-factor authentication requirements",
                file_path=str(file_path),
                remediation_steps=["Add multi-factor authentication requirements to policy"]
            ))
        
        # Check for role-based access control
        rbac_terms = ['role-based', 'rbac', 'roles', 'permissions']
        if not any(term in content.lower() for term in rbac_terms):
            violations.append(GovernanceViolation(
                violation_id="access_control_missing_rbac",
                policy_name=policy_config['name'],
                severity='medium',
                description="Access control policy should specify role-based access control",
                file_path=str(file_path),
                remediation_steps=["Add role-based access control requirements to policy"]
            ))
        
        return violations
    
    def _validate_incident_response_policy(self, file_path: Path, content: str, 
                                         policy_config: Dict[str, Any]) -> List[GovernanceViolation]:
        """Validate incident response policy specific requirements"""
        violations = []
        
        # Check for response timeframes
        timeframe_patterns = [
            r'\d+\s*(hour|hr|minute|min)',
            r'within\s+\d+',
            r'immediately',
            r'asap'
        ]
        
        if not any(re.search(pattern, content, re.IGNORECASE) for pattern in timeframe_patterns):
            violations.append(GovernanceViolation(
                violation_id="incident_response_missing_timeframes",
                policy_name=policy_config['name'],
                severity='medium',
                description="Incident response policy should specify response timeframes",
                file_path=str(file_path),
                remediation_steps=["Add specific response timeframes to incident response procedures"]
            ))
        
        # Check for contact information
        contact_terms = ['contact', 'phone', 'email', 'escalation', 'notification']
        if not any(term in content.lower() for term in contact_terms):
            violations.append(GovernanceViolation(
                violation_id="incident_response_missing_contacts",
                policy_name=policy_config['name'],
                severity='high',
                description="Incident response policy should include contact information",
                file_path=str(file_path),
                remediation_steps=["Add contact information and escalation procedures"]
            ))
        
        return violations
    
    def _validate_data_classification_policy(self, file_path: Path, content: str, 
                                           policy_config: Dict[str, Any]) -> List[GovernanceViolation]:
        """Validate data classification policy specific requirements"""
        violations = []
        
        # Check for classification levels
        classification_levels = ['public', 'internal', 'confidential', 'restricted', 'secret']
        found_levels = [level for level in classification_levels if level in content.lower()]
        
        if len(found_levels) < 3:
            violations.append(GovernanceViolation(
                violation_id="data_classification_insufficient_levels",
                policy_name=policy_config['name'],
                severity='medium',
                description=f"Data classification policy should define at least 3 classification levels. Found: {', '.join(found_levels)}",
                file_path=str(file_path),
                remediation_steps=["Define comprehensive data classification levels (e.g., Public, Internal, Confidential, Restricted)"]
            ))
        
        # Check for handling requirements
        handling_terms = ['handling', 'storage', 'transmission', 'disposal', 'retention']
        if not any(term in content.lower() for term in handling_terms):
            violations.append(GovernanceViolation(
                violation_id="data_classification_missing_handling",
                policy_name=policy_config['name'],
                severity='medium',
                description="Data classification policy should specify data handling requirements",
                file_path=str(file_path),
                remediation_steps=["Add data handling, storage, and disposal requirements for each classification level"]
            ))
        
        return violations
    
    def _validate_framework_compliance(self, target_path: Path, framework: str, 
                                     policy_results: List[PolicyComplianceResult]) -> PolicyComplianceResult:
        """Validate compliance with a specific framework"""
        framework_config = self.framework_requirements.get(framework, {})
        violations = []
        recommendations = []
        
        # Check required policies for framework
        required_policies = framework_config.get('required_policies', [])
        policy_names = [result.policy_name for result in policy_results]
        
        for required_policy in required_policies:
            policy_config = self.governance_policies.get(required_policy, {})
            policy_name = policy_config.get('name', required_policy)
            
            # Find matching policy result
            matching_result = None
            for result in policy_results:
                if policy_name in result.policy_name or required_policy in result.policy_name.lower().replace(' ', '_'):
                    matching_result = result
                    break
            
            if not matching_result or matching_result.compliance_status == 'non_compliant':
                violations.append(GovernanceViolation(
                    violation_id=f"{framework.lower()}_missing_{required_policy}",
                    policy_name=f"{framework} Framework Compliance",
                    severity='high',
                    description=f"{framework} requires {policy_name} policy",
                    remediation_steps=[f"Implement {policy_name} policy to meet {framework} requirements"],
                    compliance_framework=framework
                ))
        
        # Check documentation standards
        doc_standards = framework_config.get('documentation_standards', [])
        if doc_standards:
            # This would require checking all policy documents for these standards
            # For now, we'll add a general recommendation
            recommendations.append(f"Ensure all policies meet {framework} documentation standards: {', '.join(doc_standards)}")
        
        # Calculate framework compliance score
        if required_policies:
            compliant_policies = 0
            for required_policy in required_policies:
                policy_config = self.governance_policies.get(required_policy, {})
                policy_name = policy_config.get('name', required_policy)
                
                for result in policy_results:
                    if (policy_name in result.policy_name or 
                        required_policy in result.policy_name.lower().replace(' ', '_')):
                        if result.compliance_status in ['compliant', 'partial']:
                            compliant_policies += 1
                        break
            
            compliance_score = compliant_policies / len(required_policies)
        else:
            compliance_score = 1.0
        
        # Determine compliance status
        if compliance_score >= 0.9:
            compliance_status = 'compliant'
        elif compliance_score >= 0.7:
            compliance_status = 'partial'
        else:
            compliance_status = 'non_compliant'
        
        return PolicyComplianceResult(
            policy_name=f"{framework} Framework Compliance",
            compliance_status=compliance_status,
            compliance_score=compliance_score,
            violations=violations,
            recommendations=recommendations
        )
    
    def _has_section(self, content: str, section: str) -> bool:
        """Check if content has a specific section"""
        patterns = [
            rf'^#{1,6}\s+.*{re.escape(section)}.*$',
            rf'^{re.escape(section)}:?\s*$',
            rf'## {re.escape(section)}',
            rf'\*\*{re.escape(section)}\*\*',
        ]
        
        for pattern in patterns:
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                return True
        
        return False
    
    def _calculate_overall_compliance_score(self, policy_results: List[PolicyComplianceResult]) -> float:
        """Calculate overall compliance score"""
        if not policy_results:
            return 0.0
        
        # Weight critical policies more heavily
        weighted_scores = []
        for result in policy_results:
            # Determine weight based on policy importance
            if 'access control' in result.policy_name.lower():
                weight = 3.0  # Critical
            elif 'incident response' in result.policy_name.lower():
                weight = 2.5  # High
            elif 'data classification' in result.policy_name.lower():
                weight = 2.0  # High
            else:
                weight = 1.0  # Standard
            
            weighted_scores.append(result.compliance_score * weight)
        
        total_weight = sum([3.0 if 'access control' in r.policy_name.lower() else
                           2.5 if 'incident response' in r.policy_name.lower() else
                           2.0 if 'data classification' in r.policy_name.lower() else
                           1.0 for r in policy_results])
        
        if total_weight > 0:
            overall_score = sum(weighted_scores) / total_weight
        else:
            overall_score = 0.0
        
        return round(overall_score, 2)
    
    def _generate_governance_recommendations(self, policy_results: List[PolicyComplianceResult],
                                           critical_violations: List[GovernanceViolation],
                                           frameworks: List[str]) -> List[str]:
        """Generate governance recommendations"""
        recommendations = []
        
        # Address critical violations first
        if critical_violations:
            recommendations.append(f"Address {len(critical_violations)} critical governance violations immediately")
            for violation in critical_violations[:3]:  # Top 3 critical violations
                recommendations.extend(violation.remediation_steps[:1])  # First remediation step
        
        # Framework-specific recommendations
        for framework in frameworks:
            non_compliant = [r for r in policy_results if r.compliance_status == 'non_compliant' and framework in r.policy_name]
            if non_compliant:
                recommendations.append(f"Implement missing policies for {framework} compliance")
        
        # General recommendations
        partial_compliance = [r for r in policy_results if r.compliance_status == 'partial']
        if partial_compliance:
            recommendations.append(f"Improve {len(partial_compliance)} partially compliant policies")
        
        recommendations.extend([
            "Establish regular policy review and update schedule",
            "Implement policy training and awareness programs",
            "Create policy compliance monitoring and reporting"
        ])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _generate_governance_summary(self, policy_results: List[PolicyComplianceResult],
                                   overall_score: float,
                                   critical_violations: List[GovernanceViolation]) -> str:
        """Generate governance validation summary"""
        
        compliant_policies = len([r for r in policy_results if r.compliance_status == 'compliant'])
        total_policies = len(policy_results)
        
        summary = f"""Governance Validation Summary:
- Overall Compliance Score: {overall_score:.1%}
- Policy Compliance: {compliant_policies}/{total_policies} policies fully compliant
- Critical Violations: {len(critical_violations)}
- Governance Status: {'Compliant' if overall_score >= 0.8 else 'Needs Improvement' if overall_score >= 0.6 else 'Non-Compliant'}
"""
        
        if critical_violations:
            summary += f"\n⚠️  {len(critical_violations)} critical violations require immediate attention"
        
        if overall_score < 0.6:
            summary += f"\n❌ Governance compliance below acceptable threshold"
        elif overall_score < 0.8:
            summary += f"\n⚠️  Governance compliance needs improvement"
        else:
            summary += f"\n✅ Governance compliance meets requirements"
        
        return summary