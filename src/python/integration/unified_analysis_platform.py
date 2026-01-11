"""
Unified Analysis Platform

This module provides the central integration layer that connects all analysis components:
- Python AI Security Analyst
- Go Security Intelligence Analyzer  
- C++ Performance Security Analyzer
- Data Intelligence Layer

Provides unified API, workflow orchestration, and cross-component result correlation.
"""

import asyncio
import json
import logging
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
import concurrent.futures

# Import analysis components
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from ai_analyst.oss_security_analyst import OSSSecurityAnalyst, SecurityAnalysisReport, ComplianceAnalysisReport, SecurityPatternReport
from data_intelligence.oss_data_intelligence import OSSDataIntelligence, AccessPatternReport, GovernanceAnalysisReport, PolicyRecommendationReport
from data_intelligence.models import AccessLog, DataAsset, LocalPolicy, AccessType, DataClassification, PolicyType

# Import documentation analysis components
from .documentation_analyzer import DocumentationAnalyzer, DocumentationAnalysisReport
from .governance_validator import GovernanceValidator, GovernanceValidationReport
from .deployment_analyzer import DeploymentAnalyzer, DeploymentReadinessReport


@dataclass
class UnifiedAnalysisRequest:
    """Request for unified analysis across all components"""
    analysis_id: str
    target_path: str
    analysis_types: List[str]  # ['security', 'compliance', 'performance', 'governance']
    include_recommendations: bool = True
    include_cross_component_correlation: bool = True
    metadata: Dict[str, Any] = None


@dataclass
class ComponentAnalysisResult:
    """Result from individual component analysis"""
    component_name: str
    analysis_type: str
    status: str  # 'success', 'error', 'partial'
    result_data: Dict[str, Any]
    execution_time_seconds: float
    error_message: Optional[str] = None


@dataclass
class CrossComponentInsight:
    """Insight derived from correlating multiple component results"""
    insight_id: str
    insight_type: str
    description: str
    contributing_components: List[str]
    confidence_score: float
    recommendations: List[str]
    supporting_evidence: Dict[str, Any]


@dataclass
class UnifiedAnalysisReport:
    """Comprehensive analysis report from all components"""
    analysis_id: str
    timestamp: datetime
    target_path: str
    component_results: List[ComponentAnalysisResult]
    cross_component_insights: List[CrossComponentInsight]
    unified_recommendations: List[str]
    overall_security_score: float
    analysis_summary: str
    execution_metadata: Dict[str, Any]


class GoSecurityAnalyzerClient:
    """Client for interacting with Go Security Analyzer"""
    
    def __init__(self, binary_path: str = "src/go/security_analyzer/main"):
        self.binary_path = binary_path
        self.logger = logging.getLogger(__name__)
    
    async def analyze_with_semgrep(self, codebase_path: str) -> Dict[str, Any]:
        """Run Semgrep analysis via Go analyzer"""
        try:
            # Build Go analyzer if needed
            await self._ensure_go_binary_built()
            
            # Run analysis
            cmd = [self.binary_path, "semgrep", codebase_path]
            result = await self._run_async_command(cmd)
            
            if result['returncode'] == 0:
                return {
                    'status': 'success',
                    'findings': json.loads(result['stdout']) if result['stdout'] else [],
                    'execution_time': result['execution_time']
                }
            else:
                return {
                    'status': 'error',
                    'error': result['stderr'],
                    'execution_time': result['execution_time']
                }
        except Exception as e:
            self.logger.error(f"Go Semgrep analysis failed: {e}")
            return {'status': 'error', 'error': str(e), 'execution_time': 0}
    
    async def analyze_secrets_with_gitleaks(self, content_path: str) -> Dict[str, Any]:
        """Run Gitleaks analysis via Go analyzer"""
        try:
            await self._ensure_go_binary_built()
            
            cmd = [self.binary_path, "gitleaks", content_path]
            result = await self._run_async_command(cmd)
            
            if result['returncode'] == 0:
                return {
                    'status': 'success',
                    'secrets': json.loads(result['stdout']) if result['stdout'] else [],
                    'execution_time': result['execution_time']
                }
            else:
                return {
                    'status': 'error',
                    'error': result['stderr'],
                    'execution_time': result['execution_time']
                }
        except Exception as e:
            self.logger.error(f"Go Gitleaks analysis failed: {e}")
            return {'status': 'error', 'error': str(e), 'execution_time': 0}
    
    async def analyze_with_wazuh(self, events_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Run Wazuh analysis via Go analyzer"""
        try:
            await self._ensure_go_binary_built()
            
            # Write events to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(events_data, f)
                events_file = f.name
            
            try:
                cmd = [self.binary_path, "wazuh", events_file]
                result = await self._run_async_command(cmd)
                
                if result['returncode'] == 0:
                    return {
                        'status': 'success',
                        'threat_intelligence': json.loads(result['stdout']) if result['stdout'] else {},
                        'execution_time': result['execution_time']
                    }
                else:
                    return {
                        'status': 'error',
                        'error': result['stderr'],
                        'execution_time': result['execution_time']
                    }
            finally:
                os.unlink(events_file)
                
        except Exception as e:
            self.logger.error(f"Go Wazuh analysis failed: {e}")
            return {'status': 'error', 'error': str(e), 'execution_time': 0}
    
    async def _ensure_go_binary_built(self):
        """Ensure Go binary is built"""
        binary_path = Path(self.binary_path)
        if not binary_path.exists():
            # Build the Go binary
            go_dir = binary_path.parent
            build_cmd = ["go", "build", "-o", binary_path.name, "."]
            
            result = await self._run_async_command(build_cmd, cwd=str(go_dir))
            if result['returncode'] != 0:
                raise RuntimeError(f"Failed to build Go analyzer: {result['stderr']}")
    
    async def _run_async_command(self, cmd: List[str], cwd: str = None) -> Dict[str, Any]:
        """Run command asynchronously"""
        start_time = datetime.now()
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        
        stdout, stderr = await process.communicate()
        execution_time = (datetime.now() - start_time).total_seconds()
        
        return {
            'returncode': process.returncode,
            'stdout': stdout.decode('utf-8') if stdout else '',
            'stderr': stderr.decode('utf-8') if stderr else '',
            'execution_time': execution_time
        }


class CppPerformanceAnalyzerClient:
    """Client for interacting with C++ Performance Analyzer"""
    
    def __init__(self, binary_path: str = "src/cpp/performance_analyzer/main"):
        self.binary_path = binary_path
        self.logger = logging.getLogger(__name__)
    
    async def analyze_crypto_patterns(self, codebase_path: str) -> Dict[str, Any]:
        """Run crypto pattern analysis via C++ analyzer"""
        try:
            await self._ensure_cpp_binary_built()
            
            cmd = [self.binary_path, "crypto", codebase_path]
            result = await self._run_async_command(cmd)
            
            if result['returncode'] == 0:
                return {
                    'status': 'success',
                    'crypto_patterns': json.loads(result['stdout']) if result['stdout'] else {},
                    'execution_time': result['execution_time']
                }
            else:
                return {
                    'status': 'error',
                    'error': result['stderr'],
                    'execution_time': result['execution_time']
                }
        except Exception as e:
            self.logger.error(f"C++ crypto analysis failed: {e}")
            return {'status': 'error', 'error': str(e), 'execution_time': 0}
    
    async def analyze_performance_security(self, data_file: str) -> Dict[str, Any]:
        """Run performance security analysis via C++ analyzer"""
        try:
            await self._ensure_cpp_binary_built()
            
            cmd = [self.binary_path, "performance", data_file]
            result = await self._run_async_command(cmd)
            
            if result['returncode'] == 0:
                return {
                    'status': 'success',
                    'performance_metrics': json.loads(result['stdout']) if result['stdout'] else {},
                    'execution_time': result['execution_time']
                }
            else:
                return {
                    'status': 'error',
                    'error': result['stderr'],
                    'execution_time': result['execution_time']
                }
        except Exception as e:
            self.logger.error(f"C++ performance analysis failed: {e}")
            return {'status': 'error', 'error': str(e), 'execution_time': 0}
    
    async def _ensure_cpp_binary_built(self):
        """Ensure C++ binary is built"""
        binary_path = Path(self.binary_path)
        if not binary_path.exists():
            # Build the C++ binary
            cpp_dir = binary_path.parent
            
            # Try different build approaches
            build_commands = [
                ["g++", "-std=c++17", "-O2", "-o", binary_path.name, "*.cpp", "-lssl", "-lcrypto", "-lsodium"],
                ["clang++", "-std=c++17", "-O2", "-o", binary_path.name, "*.cpp", "-lssl", "-lcrypto", "-lsodium"],
                ["make", binary_path.name]  # If Makefile exists
            ]
            
            for build_cmd in build_commands:
                try:
                    result = await self._run_async_command(build_cmd, cwd=str(cpp_dir))
                    if result['returncode'] == 0:
                        break
                except Exception:
                    continue
            else:
                raise RuntimeError("Failed to build C++ analyzer with any available compiler")
    
    async def _run_async_command(self, cmd: List[str], cwd: str = None) -> Dict[str, Any]:
        """Run command asynchronously"""
        start_time = datetime.now()
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        
        stdout, stderr = await process.communicate()
        execution_time = (datetime.now() - start_time).total_seconds()
        
        return {
            'returncode': process.returncode,
            'stdout': stdout.decode('utf-8') if stdout else '',
            'stderr': stderr.decode('utf-8') if stderr else '',
            'execution_time': execution_time
        }


class UnifiedAnalysisPlatform:
    """
    Unified Analysis Platform
    
    Central orchestration layer that coordinates analysis across all components:
    - Python AI Security Analyst
    - Go Security Intelligence Analyzer
    - C++ Performance Security Analyzer
    - Data Intelligence Layer
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # Initialize component clients
        self.ai_analyst = OSSSecurityAnalyst()
        self.data_intelligence = OSSDataIntelligence()
        self.go_analyzer = GoSecurityAnalyzerClient()
        self.cpp_analyzer = CppPerformanceAnalyzerClient()
        
        # Initialize documentation analysis components
        self.documentation_analyzer = DocumentationAnalyzer()
        self.governance_validator = GovernanceValidator()
        self.deployment_analyzer = DeploymentAnalyzer()
        
        # Analysis workflow configuration
        self.max_concurrent_analyses = 4
        self.analysis_timeout_seconds = 300  # 5 minutes per component
        
        self.logger.info("Unified Analysis Platform initialized with documentation analysis capabilities")
    
    async def run_unified_analysis(self, request: UnifiedAnalysisRequest) -> UnifiedAnalysisReport:
        """
        Run comprehensive analysis across all requested components
        
        Args:
            request: Analysis request specifying target and analysis types
            
        Returns:
            UnifiedAnalysisReport with results from all components and cross-component insights
        """
        self.logger.info(f"Starting unified analysis {request.analysis_id} for {request.target_path}")
        start_time = datetime.now()
        
        # Run component analyses concurrently
        component_results = await self._run_component_analyses(request)
        
        # Generate cross-component insights
        insights = []
        if request.include_cross_component_correlation:
            insights = self._generate_cross_component_insights(component_results)
        
        # Generate unified recommendations
        unified_recommendations = []
        if request.include_recommendations:
            unified_recommendations = self._generate_unified_recommendations(component_results, insights)
        
        # Calculate overall security score
        security_score = self._calculate_overall_security_score(component_results)
        
        # Generate analysis summary
        summary = self._generate_analysis_summary(component_results, insights)
        
        execution_time = (datetime.now() - start_time).total_seconds()
        
        report = UnifiedAnalysisReport(
            analysis_id=request.analysis_id,
            timestamp=start_time,
            target_path=request.target_path,
            component_results=component_results,
            cross_component_insights=insights,
            unified_recommendations=unified_recommendations,
            overall_security_score=security_score,
            analysis_summary=summary,
            execution_metadata={
                'total_execution_time_seconds': execution_time,
                'components_analyzed': len(component_results),
                'successful_analyses': len([r for r in component_results if r.status == 'success']),
                'analysis_types_requested': request.analysis_types
            }
        )
        
        self.logger.info(f"Unified analysis {request.analysis_id} completed in {execution_time:.2f}s")
        return report
    
    async def _run_component_analyses(self, request: UnifiedAnalysisRequest) -> List[ComponentAnalysisResult]:
        """Run analyses across all requested components concurrently"""
        tasks = []
        
        # Python AI Analyst tasks
        if 'security' in request.analysis_types:
            tasks.append(self._run_ai_security_analysis(request.target_path))
        
        if 'compliance' in request.analysis_types:
            tasks.append(self._run_ai_compliance_analysis(request.target_path))
        
        # Go Security Analyzer tasks
        if 'sast' in request.analysis_types:
            tasks.append(self._run_go_sast_analysis(request.target_path))
        
        if 'secrets' in request.analysis_types:
            tasks.append(self._run_go_secrets_analysis(request.target_path))
        
        # C++ Performance Analyzer tasks
        if 'performance' in request.analysis_types:
            tasks.append(self._run_cpp_performance_analysis(request.target_path))
        
        if 'crypto' in request.analysis_types:
            tasks.append(self._run_cpp_crypto_analysis(request.target_path))
        
        # Data Intelligence tasks
        if 'governance' in request.analysis_types:
            tasks.append(self._run_data_governance_analysis(request.target_path))
        
        # Documentation Analysis tasks
        if 'documentation' in request.analysis_types:
            tasks.append(self._run_documentation_analysis(request.target_path))
        
        if 'governance_validation' in request.analysis_types:
            tasks.append(self._run_governance_validation(request.target_path))
        
        if 'deployment_readiness' in request.analysis_types:
            tasks.append(self._run_deployment_readiness_analysis(request.target_path))
        
        # Run tasks concurrently with timeout
        results = []
        if tasks:
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.analysis_timeout_seconds
                )
            except asyncio.TimeoutError:
                self.logger.error("Analysis timeout exceeded")
                results = [ComponentAnalysisResult(
                    component_name="timeout",
                    analysis_type="timeout",
                    status="error",
                    result_data={},
                    execution_time_seconds=self.analysis_timeout_seconds,
                    error_message="Analysis timeout exceeded"
                )]
        
        # Filter out exceptions and convert to ComponentAnalysisResult
        valid_results = []
        for result in results:
            if isinstance(result, ComponentAnalysisResult):
                valid_results.append(result)
            elif isinstance(result, Exception):
                self.logger.error(f"Component analysis failed: {result}")
                valid_results.append(ComponentAnalysisResult(
                    component_name="unknown",
                    analysis_type="error",
                    status="error",
                    result_data={},
                    execution_time_seconds=0,
                    error_message=str(result)
                ))
        
        return valid_results
    
    async def _run_ai_security_analysis(self, target_path: str) -> ComponentAnalysisResult:
        """Run Python AI security analysis"""
        start_time = datetime.now()
        
        try:
            report = self.ai_analyst.analyze_repository(target_path)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ComponentAnalysisResult(
                component_name="python_ai_analyst",
                analysis_type="security_analysis",
                status="success",
                result_data=asdict(report),
                execution_time_seconds=execution_time
            )
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"AI security analysis failed: {e}")
            
            return ComponentAnalysisResult(
                component_name="python_ai_analyst",
                analysis_type="security_analysis",
                status="error",
                result_data={},
                execution_time_seconds=execution_time,
                error_message=str(e)
            )
    
    async def _run_ai_compliance_analysis(self, target_path: str) -> ComponentAnalysisResult:
        """Run Python AI compliance analysis"""
        start_time = datetime.now()
        
        try:
            # Create mock SDD artifacts for analysis
            from ai_analyst.models import SDDArtifacts
            
            target_path_obj = Path(target_path)
            artifacts = SDDArtifacts(
                requirements_exists=(target_path_obj / "requirements.md").exists(),
                design_exists=(target_path_obj / "design.md").exists(),
                tasks_exists=(target_path_obj / "tasks.md").exists(),
                requirements_md=(target_path_obj / "requirements.md").read_text() if (target_path_obj / "requirements.md").exists() else None,
                design_md=(target_path_obj / "design.md").read_text() if (target_path_obj / "design.md").exists() else None,
                tasks_md=(target_path_obj / "tasks.md").read_text() if (target_path_obj / "tasks.md").exists() else None
            )
            
            report = self.ai_analyst.validate_sdd_compliance(artifacts)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ComponentAnalysisResult(
                component_name="python_ai_analyst",
                analysis_type="compliance_analysis",
                status="success",
                result_data=asdict(report),
                execution_time_seconds=execution_time
            )
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"AI compliance analysis failed: {e}")
            
            return ComponentAnalysisResult(
                component_name="python_ai_analyst",
                analysis_type="compliance_analysis",
                status="error",
                result_data={},
                execution_time_seconds=execution_time,
                error_message=str(e)
            )
    
    async def _run_go_sast_analysis(self, target_path: str) -> ComponentAnalysisResult:
        """Run Go SAST analysis"""
        start_time = datetime.now()
        
        try:
            result = await self.go_analyzer.analyze_with_semgrep(target_path)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ComponentAnalysisResult(
                component_name="go_security_analyzer",
                analysis_type="sast_analysis",
                status=result['status'],
                result_data=result,
                execution_time_seconds=execution_time,
                error_message=result.get('error')
            )
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Go SAST analysis failed: {e}")
            
            return ComponentAnalysisResult(
                component_name="go_security_analyzer",
                analysis_type="sast_analysis",
                status="error",
                result_data={},
                execution_time_seconds=execution_time,
                error_message=str(e)
            )
    
    async def _run_go_secrets_analysis(self, target_path: str) -> ComponentAnalysisResult:
        """Run Go secrets analysis"""
        start_time = datetime.now()
        
        try:
            result = await self.go_analyzer.analyze_secrets_with_gitleaks(target_path)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ComponentAnalysisResult(
                component_name="go_security_analyzer",
                analysis_type="secrets_analysis",
                status=result['status'],
                result_data=result,
                execution_time_seconds=execution_time,
                error_message=result.get('error')
            )
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Go secrets analysis failed: {e}")
            
            return ComponentAnalysisResult(
                component_name="go_security_analyzer",
                analysis_type="secrets_analysis",
                status="error",
                result_data={},
                execution_time_seconds=execution_time,
                error_message=str(e)
            )
    
    async def _run_cpp_performance_analysis(self, target_path: str) -> ComponentAnalysisResult:
        """Run C++ performance analysis"""
        start_time = datetime.now()
        
        try:
            result = await self.cpp_analyzer.analyze_performance_security(target_path)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ComponentAnalysisResult(
                component_name="cpp_performance_analyzer",
                analysis_type="performance_analysis",
                status=result['status'],
                result_data=result,
                execution_time_seconds=execution_time,
                error_message=result.get('error')
            )
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"C++ performance analysis failed: {e}")
            
            return ComponentAnalysisResult(
                component_name="cpp_performance_analyzer",
                analysis_type="performance_analysis",
                status="error",
                result_data={},
                execution_time_seconds=execution_time,
                error_message=str(e)
            )
    
    async def _run_cpp_crypto_analysis(self, target_path: str) -> ComponentAnalysisResult:
        """Run C++ crypto analysis"""
        start_time = datetime.now()
        
        try:
            result = await self.cpp_analyzer.analyze_crypto_patterns(target_path)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ComponentAnalysisResult(
                component_name="cpp_performance_analyzer",
                analysis_type="crypto_analysis",
                status=result['status'],
                result_data=result,
                execution_time_seconds=execution_time,
                error_message=result.get('error')
            )
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"C++ crypto analysis failed: {e}")
            
            return ComponentAnalysisResult(
                component_name="cpp_performance_analyzer",
                analysis_type="crypto_analysis",
                status="error",
                result_data={},
                execution_time_seconds=execution_time,
                error_message=str(e)
            )
    
    async def _run_data_governance_analysis(self, target_path: str) -> ComponentAnalysisResult:
        """Run data governance analysis"""
        start_time = datetime.now()
        
        try:
            # Create mock data assets for analysis
            mock_assets = self._create_mock_data_assets(target_path)
            
            report = self.data_intelligence.analyze_data_governance(mock_assets)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ComponentAnalysisResult(
                component_name="data_intelligence",
                analysis_type="governance_analysis",
                status="success",
                result_data=asdict(report),
                execution_time_seconds=execution_time
            )
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Data governance analysis failed: {e}")
            
            return ComponentAnalysisResult(
                component_name="data_intelligence",
                analysis_type="governance_analysis",
                status="error",
                result_data={},
                execution_time_seconds=execution_time,
                error_message=str(e)
            )
    
    def _create_mock_data_assets(self, target_path: str) -> List[DataAsset]:
        """Create mock data assets for governance analysis"""
        assets = []
        target_path_obj = Path(target_path)
        
        # Find data files in target path
        data_extensions = ['.json', '.csv', '.yaml', '.yml', '.xml', '.db', '.sqlite']
        
        for file_path in target_path_obj.rglob("*"):
            if file_path.is_file() and file_path.suffix.lower() in data_extensions:
                asset = DataAsset(
                    asset_id=f"asset_{hash(str(file_path))}",
                    name=file_path.name,
                    description=f"Data file: {file_path.name}",
                    minio_bucket="analysis-bucket",
                    duckdb_table=file_path.stem,
                    local_file_path=str(file_path),
                    classification=DataClassification.INTERNAL,
                    owner="system",
                    created_at=datetime.fromtimestamp(file_path.stat().st_ctime),
                    updated_at=datetime.fromtimestamp(file_path.stat().st_mtime),
                    size_bytes=file_path.stat().st_size,
                    record_count=0,
                    policies=[]
                )
                assets.append(asset)
        
        return assets
    
    async def _run_documentation_analysis(self, target_path: str) -> ComponentAnalysisResult:
        """Run documentation completeness analysis"""
        start_time = datetime.now()
        
        try:
            report = self.documentation_analyzer.analyze_documentation_completeness(target_path)
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ComponentAnalysisResult(
                component_name="documentation_analyzer",
                analysis_type="documentation_analysis",
                status="success",
                result_data={
                    'analysis_id': report.analysis_id,
                    'quality_score': report.quality_score,
                    'documentation_gaps': len(report.documentation_gaps),
                    'critical_gaps': len([g for g in report.documentation_gaps if g.severity == 'critical']),
                    'setup_validation_results': len(report.setup_validation_results),
                    'deployment_readiness': report.deployment_readiness.overall_readiness,
                    'deployment_score': report.deployment_readiness.readiness_score,
                    'summary': report.summary,
                    'recommendations': [
                        gap.recommendations[0] if gap.recommendations else f"Address {gap.description}"
                        for gap in report.documentation_gaps[:5]
                    ]
                },
                execution_time_seconds=execution_time
            )
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Documentation analysis failed: {e}")
            
            return ComponentAnalysisResult(
                component_name="documentation_analyzer",
                analysis_type="documentation_analysis",
                status="error",
                result_data={},
                execution_time_seconds=execution_time,
                error_message=str(e)
            )
    
    async def _run_governance_validation(self, target_path: str) -> ComponentAnalysisResult:
        """Run governance workflow validation"""
        start_time = datetime.now()
        
        try:
            # Use SOC2 as default compliance framework
            report = self.governance_validator.validate_governance_workflows(
                target_path, compliance_frameworks=['SOC2']
            )
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ComponentAnalysisResult(
                component_name="governance_validator",
                analysis_type="governance_validation",
                status="success",
                result_data={
                    'validation_id': report.validation_id,
                    'overall_compliance_score': report.overall_compliance_score,
                    'policy_compliance_results': len(report.policy_compliance_results),
                    'critical_violations': len(report.critical_violations),
                    'compliance_frameworks': report.compliance_frameworks,
                    'summary': report.summary,
                    'recommendations': report.recommendations[:5]
                },
                execution_time_seconds=execution_time
            )
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Governance validation failed: {e}")
            
            return ComponentAnalysisResult(
                component_name="governance_validator",
                analysis_type="governance_validation",
                status="error",
                result_data={},
                execution_time_seconds=execution_time,
                error_message=str(e)
            )
    
    async def _run_deployment_readiness_analysis(self, target_path: str) -> ComponentAnalysisResult:
        """Run deployment readiness analysis"""
        start_time = datetime.now()
        
        try:
            # Default to production environment for comprehensive analysis
            report = self.deployment_analyzer.analyze_deployment_readiness(
                target_path, deployment_environment="production"
            )
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return ComponentAnalysisResult(
                component_name="deployment_analyzer",
                analysis_type="deployment_readiness",
                status="success",
                result_data={
                    'analysis_id': report.analysis_id,
                    'overall_readiness': report.overall_readiness,
                    'readiness_score': report.readiness_score,
                    'security_score': report.security_assessment.security_score,
                    'operational_score': report.operational_assessment.operational_score,
                    'deployment_issues': len(report.deployment_issues),
                    'critical_issues': len([i for i in report.deployment_issues if i.severity == 'critical']),
                    'infrastructure_requirements': len(report.infrastructure_requirements),
                    'summary': report.summary,
                    'recommendations': report.recommendations[:5]
                },
                execution_time_seconds=execution_time
            )
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Deployment readiness analysis failed: {e}")
            
            return ComponentAnalysisResult(
                component_name="deployment_analyzer",
                analysis_type="deployment_readiness",
                status="error",
                result_data={},
                execution_time_seconds=execution_time,
                error_message=str(e)
            )
    
    def _generate_cross_component_insights(self, component_results: List[ComponentAnalysisResult]) -> List[CrossComponentInsight]:
        """Generate insights by correlating results across components"""
        insights = []
        
        # Get successful results by component
        successful_results = {r.component_name: r for r in component_results if r.status == 'success'}
        
        # Insight 1: Security pattern correlation
        if 'python_ai_analyst' in successful_results and 'go_security_analyzer' in successful_results:
            ai_result = successful_results['python_ai_analyst']
            go_result = successful_results['go_security_analyzer']
            
            # Check for overlapping security findings
            ai_findings = ai_result.result_data.get('security_findings', [])
            go_findings = go_result.result_data.get('findings', [])
            
            if ai_findings and go_findings:
                insights.append(CrossComponentInsight(
                    insight_id="security_pattern_correlation",
                    insight_type="security_validation",
                    description=f"AI analyst identified {len(ai_findings)} security patterns, Go analyzer found {len(go_findings)} SAST findings",
                    contributing_components=['python_ai_analyst', 'go_security_analyzer'],
                    confidence_score=0.8,
                    recommendations=[
                        "Cross-validate security findings between AI analysis and SAST tools",
                        "Prioritize issues identified by multiple analysis methods"
                    ],
                    supporting_evidence={
                        'ai_findings_count': len(ai_findings),
                        'sast_findings_count': len(go_findings)
                    }
                ))
        
        # Insight 2: Performance vs Security trade-offs
        if 'cpp_performance_analyzer' in successful_results and 'python_ai_analyst' in successful_results:
            cpp_result = successful_results['cpp_performance_analyzer']
            ai_result = successful_results['python_ai_analyst']
            
            crypto_patterns = cpp_result.result_data.get('crypto_patterns', {})
            security_score = ai_result.result_data.get('confidence_score', 0)
            
            if crypto_patterns and security_score:
                insights.append(CrossComponentInsight(
                    insight_id="performance_security_tradeoff",
                    insight_type="optimization_opportunity",
                    description="Performance analysis reveals crypto usage patterns that may impact security posture",
                    contributing_components=['cpp_performance_analyzer', 'python_ai_analyst'],
                    confidence_score=0.7,
                    recommendations=[
                        "Review cryptographic implementations for performance vs security balance",
                        "Consider hardware acceleration for crypto operations"
                    ],
                    supporting_evidence={
                        'crypto_patterns_found': bool(crypto_patterns),
                        'security_confidence': security_score
                    }
                ))
        
        # Insight 3: Governance and compliance alignment
        if 'data_intelligence' in successful_results and 'python_ai_analyst' in successful_results:
            data_result = successful_results['data_intelligence']
            ai_result = successful_results['python_ai_analyst']
            
            compliance_score = data_result.result_data.get('compliance_score', 0)
            sdd_compliance = ai_result.result_data.get('compliance_status', 'unknown')
            
            if compliance_score and sdd_compliance:
                insights.append(CrossComponentInsight(
                    insight_id="governance_compliance_alignment",
                    insight_type="compliance_validation",
                    description=f"Data governance compliance ({compliance_score}%) aligns with SDD compliance ({sdd_compliance})",
                    contributing_components=['data_intelligence', 'python_ai_analyst'],
                    confidence_score=0.9,
                    recommendations=[
                        "Maintain alignment between data governance and development practices",
                        "Implement automated compliance monitoring across all domains"
                    ],
                    supporting_evidence={
                        'data_compliance_score': compliance_score,
                        'sdd_compliance_status': sdd_compliance
                    }
                ))
        
        return insights
    
    def _generate_unified_recommendations(self, component_results: List[ComponentAnalysisResult], 
                                        insights: List[CrossComponentInsight]) -> List[str]:
        """Generate unified recommendations across all components"""
        recommendations = []
        
        # Collect recommendations from all components
        component_recommendations = []
        for result in component_results:
            if result.status == 'success':
                result_recommendations = result.result_data.get('recommendations', [])
                if isinstance(result_recommendations, list):
                    component_recommendations.extend(result_recommendations)
        
        # Add insight-based recommendations
        for insight in insights:
            component_recommendations.extend(insight.recommendations)
        
        # Deduplicate and prioritize recommendations
        unique_recommendations = list(set(component_recommendations))
        
        # Prioritize based on frequency and component importance
        recommendation_scores = {}
        for rec in component_recommendations:
            recommendation_scores[rec] = recommendation_scores.get(rec, 0) + 1
        
        # Sort by score (frequency) and add to final list
        sorted_recommendations = sorted(unique_recommendations, 
                                      key=lambda x: recommendation_scores.get(x, 0), 
                                      reverse=True)
        
        # Add top-level unified recommendations
        recommendations.extend([
            "Implement comprehensive security monitoring across all analysis domains",
            "Establish regular cross-component analysis workflows",
            "Maintain alignment between security, performance, and governance requirements"
        ])
        
        # Add component-specific recommendations (top 10)
        recommendations.extend(sorted_recommendations[:10])
        
        return recommendations
    
    def _calculate_overall_security_score(self, component_results: List[ComponentAnalysisResult]) -> float:
        """Calculate overall security score from all component results"""
        scores = []
        weights = {
            'python_ai_analyst': 0.3,
            'go_security_analyzer': 0.3,
            'cpp_performance_analyzer': 0.2,
            'data_intelligence': 0.2
        }
        
        for result in component_results:
            if result.status == 'success':
                component_weight = weights.get(result.component_name, 0.1)
                
                # Extract score based on component type
                if result.component_name == 'python_ai_analyst':
                    score = result.result_data.get('confidence_score', 0.5)
                elif result.component_name == 'go_security_analyzer':
                    findings = result.result_data.get('findings', [])
                    score = max(0.0, 1.0 - (len(findings) * 0.1))  # Reduce score for findings
                elif result.component_name == 'cpp_performance_analyzer':
                    score = 0.8  # Default good score for performance analysis
                elif result.component_name == 'data_intelligence':
                    score = result.result_data.get('compliance_score', 50) / 100.0
                else:
                    score = 0.5  # Default neutral score
                
                scores.append(score * component_weight)
        
        # Calculate weighted average
        if scores:
            overall_score = sum(scores) / sum(weights.values())
        else:
            overall_score = 0.0
        
        return round(overall_score, 2)
    
    def _generate_analysis_summary(self, component_results: List[ComponentAnalysisResult], 
                                 insights: List[CrossComponentInsight]) -> str:
        """Generate comprehensive analysis summary"""
        successful_components = [r for r in component_results if r.status == 'success']
        failed_components = [r for r in component_results if r.status == 'error']
        
        summary = f"""Unified Analysis Summary:
- Components analyzed: {len(component_results)}
- Successful analyses: {len(successful_components)}
- Failed analyses: {len(failed_components)}
- Cross-component insights: {len(insights)}
- Analysis types: {', '.join(set(r.analysis_type for r in component_results))}
"""
        
        if successful_components:
            summary += f"\nSuccessful components: {', '.join(r.component_name for r in successful_components)}"
        
        if failed_components:
            summary += f"\nFailed components: {', '.join(r.component_name for r in failed_components)}"
        
        if insights:
            summary += f"\nKey insights: {', '.join(i.insight_type for i in insights)}"
        
        return summary
    
    def close(self):
        """Close all component connections"""
        try:
            self.data_intelligence.close()
            self.logger.info("Unified Analysis Platform closed")
        except Exception as e:
            self.logger.error(f"Error closing platform: {e}")