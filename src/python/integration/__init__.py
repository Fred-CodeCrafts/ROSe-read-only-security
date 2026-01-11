"""
Integration Package

Unified Analysis Platform Integration Layer

This package provides the central integration layer that connects all analysis components:
- Python AI Security Analyst
- Go Security Intelligence Analyzer  
- C++ Performance Security Analyzer
- Data Intelligence Layer

Key Components:
- UnifiedAnalysisPlatform: Central orchestration and API
- AnalysisDashboard: Comprehensive reporting and visualization
- WorkflowOrchestrator: Complex workflow management and orchestration

Usage:
    from integration import UnifiedAnalysisPlatform, AnalysisDashboard, WorkflowOrchestrator
    
    # Simple unified analysis
    platform = UnifiedAnalysisPlatform()
    request = UnifiedAnalysisRequest(
        analysis_id="example_001",
        target_path="./src",
        analysis_types=["security", "compliance", "performance"]
    )
    report = await platform.run_unified_analysis(request)
    
    # Generate dashboard report
    dashboard = AnalysisDashboard()
    report_path = dashboard.generate_unified_report(report)
    
    # Complex workflow orchestration
    orchestrator = WorkflowOrchestrator()
    workflow = orchestrator.create_comprehensive_analysis_workflow("./src")
    result = await orchestrator.execute_workflow(workflow)
"""

from .unified_analysis_platform import (
    UnifiedAnalysisPlatform,
    UnifiedAnalysisRequest,
    UnifiedAnalysisReport,
    ComponentAnalysisResult,
    CrossComponentInsight,
    GoSecurityAnalyzerClient,
    CppPerformanceAnalyzerClient
)

from .analysis_dashboard import (
    AnalysisDashboard,
    create_sample_dashboard_report
)

from .workflow_orchestrator import (
    WorkflowOrchestrator,
    AnalysisWorkflow,
    WorkflowTask,
    WorkflowResult,
    WorkflowStatus,
    TaskStatus
)

__all__ = [
    # Core platform
    'UnifiedAnalysisPlatform',
    'UnifiedAnalysisRequest', 
    'UnifiedAnalysisReport',
    'ComponentAnalysisResult',
    'CrossComponentInsight',
    
    # Component clients
    'GoSecurityAnalyzerClient',
    'CppPerformanceAnalyzerClient',
    
    # Dashboard and reporting
    'AnalysisDashboard',
    'create_sample_dashboard_report',
    
    # Workflow orchestration
    'WorkflowOrchestrator',
    'AnalysisWorkflow',
    'WorkflowTask',
    'WorkflowResult',
    'WorkflowStatus',
    'TaskStatus'
]

__version__ = "1.0.0"
__author__ = "AI-Assisted Cybersecurity Analysis Platform"
__description__ = "Unified integration layer for multi-component security analysis"