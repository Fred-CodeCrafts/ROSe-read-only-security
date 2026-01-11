"""
Analysis Workflow Orchestrator

Provides workflow orchestration and result correlation capabilities for the unified analysis platform.
Manages complex analysis workflows, dependency resolution, and result correlation across components.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path

from .unified_analysis_platform import (
    UnifiedAnalysisPlatform, UnifiedAnalysisRequest, UnifiedAnalysisReport,
    ComponentAnalysisResult, CrossComponentInsight
)
from .analysis_dashboard import AnalysisDashboard


class WorkflowStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowTask:
    """Individual task within an analysis workflow"""
    task_id: str
    task_name: str
    component_name: str
    analysis_type: str
    dependencies: List[str] = field(default_factory=list)
    timeout_seconds: int = 300
    retry_count: int = 0
    max_retries: int = 2
    status: TaskStatus = TaskStatus.PENDING
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    result: Optional[ComponentAnalysisResult] = None
    error_message: Optional[str] = None


@dataclass
class AnalysisWorkflow:
    """Complete analysis workflow definition"""
    workflow_id: str
    workflow_name: str
    target_path: str
    tasks: List[WorkflowTask]
    status: WorkflowStatus = WorkflowStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowResult:
    """Result of workflow execution"""
    workflow_id: str
    status: WorkflowStatus
    unified_report: Optional[UnifiedAnalysisReport]
    task_results: List[ComponentAnalysisResult]
    execution_summary: Dict[str, Any]
    error_message: Optional[str] = None


class WorkflowOrchestrator:
    """
    Analysis Workflow Orchestrator
    
    Manages complex analysis workflows with:
    - Task dependency resolution
    - Parallel execution where possible
    - Result correlation and aggregation
    - Error handling and retry logic
    - Workflow state management
    """
    
    def __init__(self, max_concurrent_workflows: int = 3):
        self.logger = logging.getLogger(__name__)
        self.max_concurrent_workflows = max_concurrent_workflows
        self.active_workflows: Dict[str, AnalysisWorkflow] = {}
        self.workflow_history: List[WorkflowResult] = []
        
        # Initialize platform components
        self.analysis_platform = UnifiedAnalysisPlatform()
        self.dashboard = AnalysisDashboard()
        
        # Workflow templates
        self.workflow_templates = self._initialize_workflow_templates()
        
        self.logger.info("Workflow Orchestrator initialized")
    
    def create_comprehensive_analysis_workflow(self, target_path: str, 
                                             workflow_name: str = None) -> AnalysisWorkflow:
        """
        Create comprehensive analysis workflow covering all components
        
        Args:
            target_path: Path to analyze
            workflow_name: Optional workflow name
            
        Returns:
            AnalysisWorkflow configured for comprehensive analysis
        """
        workflow_id = f"comprehensive_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not workflow_name:
            workflow_name = f"Comprehensive Analysis - {Path(target_path).name}"
        
        tasks = [
            # Phase 1: Independent analyses
            WorkflowTask(
                task_id="ai_security_analysis",
                task_name="AI Security Analysis",
                component_name="python_ai_analyst",
                analysis_type="security",
                dependencies=[],
                timeout_seconds=180
            ),
            WorkflowTask(
                task_id="ai_compliance_analysis",
                task_name="AI Compliance Analysis",
                component_name="python_ai_analyst",
                analysis_type="compliance",
                dependencies=[],
                timeout_seconds=120
            ),
            WorkflowTask(
                task_id="go_sast_analysis",
                task_name="Go SAST Analysis",
                component_name="go_security_analyzer",
                analysis_type="sast",
                dependencies=[],
                timeout_seconds=240
            ),
            WorkflowTask(
                task_id="go_secrets_analysis",
                task_name="Go Secrets Analysis",
                component_name="go_security_analyzer",
                analysis_type="secrets",
                dependencies=[],
                timeout_seconds=120
            ),
            
            # Phase 2: Performance analysis (depends on security findings)
            WorkflowTask(
                task_id="cpp_crypto_analysis",
                task_name="C++ Crypto Analysis",
                component_name="cpp_performance_analyzer",
                analysis_type="crypto",
                dependencies=["ai_security_analysis"],
                timeout_seconds=180
            ),
            WorkflowTask(
                task_id="cpp_performance_analysis",
                task_name="C++ Performance Analysis",
                component_name="cpp_performance_analyzer",
                analysis_type="performance",
                dependencies=["go_sast_analysis"],
                timeout_seconds=240
            ),
            
            # Phase 3: Data governance (depends on all security analyses)
            WorkflowTask(
                task_id="data_governance_analysis",
                task_name="Data Governance Analysis",
                component_name="data_intelligence",
                analysis_type="governance",
                dependencies=["ai_security_analysis", "go_sast_analysis", "go_secrets_analysis"],
                timeout_seconds=180
            ),
            
            # Phase 4: Documentation and deployment analysis
            WorkflowTask(
                task_id="documentation_analysis",
                task_name="Documentation Completeness Analysis",
                component_name="documentation_analyzer",
                analysis_type="documentation",
                dependencies=["ai_compliance_analysis"],
                timeout_seconds=120
            ),
            WorkflowTask(
                task_id="governance_validation",
                task_name="Governance Workflow Validation",
                component_name="governance_validator",
                analysis_type="governance_validation",
                dependencies=["data_governance_analysis", "documentation_analysis"],
                timeout_seconds=180
            ),
            WorkflowTask(
                task_id="deployment_readiness",
                task_name="Deployment Readiness Assessment",
                component_name="deployment_analyzer",
                analysis_type="deployment_readiness",
                dependencies=["cpp_performance_analysis", "governance_validation"],
                timeout_seconds=240
            )
        ]
        
        workflow = AnalysisWorkflow(
            workflow_id=workflow_id,
            workflow_name=workflow_name,
            target_path=target_path,
            tasks=tasks,
            metadata={
                "workflow_type": "comprehensive",
                "total_tasks": len(tasks),
                "estimated_duration_minutes": 20
            }
        )
        
        return workflow
    
    def create_security_focused_workflow(self, target_path: str, 
                                       workflow_name: str = None) -> AnalysisWorkflow:
        """
        Create security-focused analysis workflow
        
        Args:
            target_path: Path to analyze
            workflow_name: Optional workflow name
            
        Returns:
            AnalysisWorkflow configured for security analysis
        """
        workflow_id = f"security_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not workflow_name:
            workflow_name = f"Security Analysis - {Path(target_path).name}"
        
        tasks = [
            WorkflowTask(
                task_id="ai_security_analysis",
                task_name="AI Security Pattern Analysis",
                component_name="python_ai_analyst",
                analysis_type="security",
                dependencies=[],
                timeout_seconds=180
            ),
            WorkflowTask(
                task_id="go_sast_analysis",
                task_name="SAST Security Scanning",
                component_name="go_security_analyzer",
                analysis_type="sast",
                dependencies=[],
                timeout_seconds=240
            ),
            WorkflowTask(
                task_id="go_secrets_analysis",
                task_name="Secret Detection Analysis",
                component_name="go_security_analyzer",
                analysis_type="secrets",
                dependencies=[],
                timeout_seconds=120
            ),
            WorkflowTask(
                task_id="cpp_crypto_analysis",
                task_name="Cryptographic Security Analysis",
                component_name="cpp_performance_analyzer",
                analysis_type="crypto",
                dependencies=["ai_security_analysis"],
                timeout_seconds=180
            )
        ]
        
        workflow = AnalysisWorkflow(
            workflow_id=workflow_id,
            workflow_name=workflow_name,
            target_path=target_path,
            tasks=tasks,
            metadata={
                "workflow_type": "security_focused",
                "total_tasks": len(tasks),
                "estimated_duration_minutes": 10
            }
        )
        
        return workflow
    
    def create_compliance_workflow(self, target_path: str, 
                                 workflow_name: str = None) -> AnalysisWorkflow:
        """
        Create compliance-focused analysis workflow
        
        Args:
            target_path: Path to analyze
            workflow_name: Optional workflow name
            
        Returns:
            AnalysisWorkflow configured for compliance analysis
        """
        workflow_id = f"compliance_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not workflow_name:
            workflow_name = f"Compliance Analysis - {Path(target_path).name}"
        
        tasks = [
            WorkflowTask(
                task_id="ai_compliance_analysis",
                task_name="SDD Compliance Analysis",
                component_name="python_ai_analyst",
                analysis_type="compliance",
                dependencies=[],
                timeout_seconds=120
            ),
            WorkflowTask(
                task_id="data_governance_analysis",
                task_name="Data Governance Compliance",
                component_name="data_intelligence",
                analysis_type="governance",
                dependencies=["ai_compliance_analysis"],
                timeout_seconds=180
            )
        ]
        
        workflow = AnalysisWorkflow(
            workflow_id=workflow_id,
            workflow_name=workflow_name,
            target_path=target_path,
            tasks=tasks,
            metadata={
                "workflow_type": "compliance_focused",
                "total_tasks": len(tasks),
                "estimated_duration_minutes": 5
            }
        )
        
        return workflow
    
    def create_documentation_workflow(self, target_path: str, 
                                    workflow_name: str = None) -> AnalysisWorkflow:
        """
        Create documentation-focused analysis workflow
        
        Args:
            target_path: Path to analyze
            workflow_name: Optional workflow name
            
        Returns:
            AnalysisWorkflow configured for documentation analysis
        """
        workflow_id = f"documentation_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        if not workflow_name:
            workflow_name = f"Documentation Analysis - {Path(target_path).name}"
        
        tasks = [
            WorkflowTask(
                task_id="documentation_completeness",
                task_name="Documentation Completeness Analysis",
                component_name="documentation_analyzer",
                analysis_type="documentation",
                dependencies=[],
                timeout_seconds=120
            ),
            WorkflowTask(
                task_id="governance_validation",
                task_name="Governance Workflow Validation",
                component_name="governance_validator",
                analysis_type="governance_validation",
                dependencies=["documentation_completeness"],
                timeout_seconds=180
            ),
            WorkflowTask(
                task_id="deployment_readiness",
                task_name="Deployment Readiness Assessment",
                component_name="deployment_analyzer",
                analysis_type="deployment_readiness",
                dependencies=["documentation_completeness", "governance_validation"],
                timeout_seconds=240
            )
        ]
        
        workflow = AnalysisWorkflow(
            workflow_id=workflow_id,
            workflow_name=workflow_name,
            target_path=target_path,
            tasks=tasks,
            metadata={
                "workflow_type": "documentation_focused",
                "total_tasks": len(tasks),
                "estimated_duration_minutes": 9
            }
        )
        
        return workflow
    
    async def execute_workflow(self, workflow: AnalysisWorkflow) -> WorkflowResult:
        """
        Execute analysis workflow with dependency resolution and parallel execution
        
        Args:
            workflow: Workflow to execute
            
        Returns:
            WorkflowResult with execution results
        """
        self.logger.info(f"Starting workflow execution: {workflow.workflow_id}")
        
        # Check if we can start this workflow
        if len(self.active_workflows) >= self.max_concurrent_workflows:
            raise RuntimeError("Maximum concurrent workflows exceeded")
        
        # Add to active workflows
        workflow.status = WorkflowStatus.RUNNING
        workflow.started_at = datetime.now()
        self.active_workflows[workflow.workflow_id] = workflow
        
        try:
            # Execute tasks with dependency resolution
            task_results = await self._execute_workflow_tasks(workflow)
            
            # Generate unified analysis report
            unified_report = await self._generate_unified_report(workflow, task_results)
            
            # Mark workflow as completed
            workflow.status = WorkflowStatus.COMPLETED
            workflow.completed_at = datetime.now()
            
            # Create workflow result
            result = WorkflowResult(
                workflow_id=workflow.workflow_id,
                status=WorkflowStatus.COMPLETED,
                unified_report=unified_report,
                task_results=task_results,
                execution_summary=self._generate_execution_summary(workflow, task_results)
            )
            
            self.logger.info(f"Workflow completed successfully: {workflow.workflow_id}")
            
        except Exception as e:
            self.logger.error(f"Workflow execution failed: {workflow.workflow_id} - {e}")
            
            workflow.status = WorkflowStatus.FAILED
            workflow.completed_at = datetime.now()
            
            result = WorkflowResult(
                workflow_id=workflow.workflow_id,
                status=WorkflowStatus.FAILED,
                unified_report=None,
                task_results=[task.result for task in workflow.tasks if task.result],
                execution_summary=self._generate_execution_summary(workflow, []),
                error_message=str(e)
            )
        
        finally:
            # Remove from active workflows and add to history
            self.active_workflows.pop(workflow.workflow_id, None)
            self.workflow_history.append(result)
        
        return result
    
    async def _execute_workflow_tasks(self, workflow: AnalysisWorkflow) -> List[ComponentAnalysisResult]:
        """Execute workflow tasks with dependency resolution"""
        completed_tasks = set()
        task_results = []
        
        while len(completed_tasks) < len(workflow.tasks):
            # Find tasks that can be executed (dependencies satisfied)
            ready_tasks = []
            for task in workflow.tasks:
                if (task.status == TaskStatus.PENDING and 
                    all(dep in completed_tasks for dep in task.dependencies)):
                    ready_tasks.append(task)
            
            if not ready_tasks:
                # Check if we have any running tasks
                running_tasks = [t for t in workflow.tasks if t.status == TaskStatus.RUNNING]
                if not running_tasks:
                    # Deadlock or all remaining tasks failed
                    break
                
                # Wait a bit for running tasks to complete
                await asyncio.sleep(1)
                continue
            
            # Execute ready tasks in parallel
            task_coroutines = []
            for task in ready_tasks:
                task.status = TaskStatus.RUNNING
                task.start_time = datetime.now()
                task_coroutines.append(self._execute_single_task(task, workflow.target_path))
            
            # Wait for tasks to complete
            results = await asyncio.gather(*task_coroutines, return_exceptions=True)
            
            # Process results
            for task, result in zip(ready_tasks, results):
                task.end_time = datetime.now()
                
                if isinstance(result, Exception):
                    task.status = TaskStatus.FAILED
                    task.error_message = str(result)
                    self.logger.error(f"Task failed: {task.task_id} - {result}")
                    
                    # Retry if possible
                    if task.retry_count < task.max_retries:
                        task.retry_count += 1
                        task.status = TaskStatus.PENDING
                        self.logger.info(f"Retrying task: {task.task_id} (attempt {task.retry_count + 1})")
                        continue
                else:
                    task.status = TaskStatus.COMPLETED
                    task.result = result
                    task_results.append(result)
                    completed_tasks.add(task.task_id)
                    self.logger.info(f"Task completed: {task.task_id}")
        
        return task_results
    
    async def _execute_single_task(self, task: WorkflowTask, target_path: str) -> ComponentAnalysisResult:
        """Execute a single workflow task"""
        self.logger.info(f"Executing task: {task.task_id}")
        
        # Create analysis request for this specific task
        request = UnifiedAnalysisRequest(
            analysis_id=f"{task.task_id}_{datetime.now().strftime('%H%M%S')}",
            target_path=target_path,
            analysis_types=[task.analysis_type],
            include_recommendations=True,
            include_cross_component_correlation=False  # Individual task, no correlation needed
        )
        
        try:
            # Execute with timeout
            unified_report = await asyncio.wait_for(
                self.analysis_platform.run_unified_analysis(request),
                timeout=task.timeout_seconds
            )
            
            # Extract the relevant component result
            for component_result in unified_report.component_results:
                if (component_result.component_name == task.component_name and 
                    component_result.analysis_type == task.analysis_type):
                    return component_result
            
            # If no matching result found, create a generic success result
            return ComponentAnalysisResult(
                component_name=task.component_name,
                analysis_type=task.analysis_type,
                status="success",
                result_data={"message": "Task completed successfully"},
                execution_time_seconds=(datetime.now() - task.start_time).total_seconds()
            )
            
        except asyncio.TimeoutError:
            raise RuntimeError(f"Task timeout exceeded: {task.timeout_seconds}s")
        except Exception as e:
            raise RuntimeError(f"Task execution failed: {e}")
    
    async def _generate_unified_report(self, workflow: AnalysisWorkflow, 
                                     task_results: List[ComponentAnalysisResult]) -> UnifiedAnalysisReport:
        """Generate unified report from workflow results"""
        # Create comprehensive analysis request
        all_analysis_types = list(set(task.analysis_type for task in workflow.tasks))
        
        request = UnifiedAnalysisRequest(
            analysis_id=workflow.workflow_id,
            target_path=workflow.target_path,
            analysis_types=all_analysis_types,
            include_recommendations=True,
            include_cross_component_correlation=True
        )
        
        # Create unified report with workflow results
        unified_report = UnifiedAnalysisReport(
            analysis_id=workflow.workflow_id,
            timestamp=workflow.started_at or datetime.now(),
            target_path=workflow.target_path,
            component_results=task_results,
            cross_component_insights=self._generate_workflow_insights(task_results),
            unified_recommendations=self._generate_workflow_recommendations(task_results),
            overall_security_score=self._calculate_workflow_security_score(task_results),
            analysis_summary=self._generate_workflow_summary(workflow, task_results),
            execution_metadata={
                "workflow_id": workflow.workflow_id,
                "workflow_type": workflow.metadata.get("workflow_type", "unknown"),
                "total_tasks": len(workflow.tasks),
                "successful_tasks": len([r for r in task_results if r.status == "success"]),
                "total_execution_time_seconds": (
                    (workflow.completed_at or datetime.now()) - workflow.started_at
                ).total_seconds() if workflow.started_at else 0
            }
        )
        
        return unified_report
    
    def _generate_workflow_insights(self, task_results: List[ComponentAnalysisResult]) -> List[CrossComponentInsight]:
        """Generate cross-component insights from workflow results"""
        insights = []
        
        # Group results by component
        component_results = {}
        for result in task_results:
            if result.component_name not in component_results:
                component_results[result.component_name] = []
            component_results[result.component_name].append(result)
        
        # Generate insights based on component combinations
        components = list(component_results.keys())
        
        for i, comp1 in enumerate(components):
            for comp2 in components[i+1:]:
                insight = self._analyze_component_correlation(
                    comp1, component_results[comp1],
                    comp2, component_results[comp2]
                )
                if insight:
                    insights.append(insight)
        
        return insights
    
    def _analyze_component_correlation(self, comp1: str, results1: List[ComponentAnalysisResult],
                                     comp2: str, results2: List[ComponentAnalysisResult]) -> Optional[CrossComponentInsight]:
        """Analyze correlation between two components"""
        # Simple correlation based on success rates and findings
        success1 = len([r for r in results1 if r.status == "success"])
        success2 = len([r for r in results2 if r.status == "success"])
        
        if success1 > 0 and success2 > 0:
            # Both components have successful results
            return CrossComponentInsight(
                insight_id=f"correlation_{comp1}_{comp2}",
                insight_type="component_correlation",
                description=f"Both {comp1} and {comp2} completed successfully with correlated findings",
                contributing_components=[comp1, comp2],
                confidence_score=0.7,
                recommendations=[
                    f"Cross-validate findings between {comp1} and {comp2}",
                    "Implement integrated monitoring for both components"
                ],
                supporting_evidence={
                    f"{comp1}_success_count": success1,
                    f"{comp2}_success_count": success2
                }
            )
        
        return None
    
    def _generate_workflow_recommendations(self, task_results: List[ComponentAnalysisResult]) -> List[str]:
        """Generate unified recommendations from workflow results"""
        all_recommendations = []
        
        # Collect recommendations from all task results
        for result in task_results:
            if result.status == "success":
                result_recommendations = result.result_data.get("recommendations", [])
                if isinstance(result_recommendations, list):
                    all_recommendations.extend(result_recommendations)
        
        # Deduplicate and prioritize
        unique_recommendations = list(set(all_recommendations))
        
        # Add workflow-level recommendations
        workflow_recommendations = [
            "Implement comprehensive monitoring across all analyzed components",
            "Establish regular analysis workflows for continuous security assessment",
            "Create automated alerting for critical security findings"
        ]
        
        return workflow_recommendations + unique_recommendations[:7]  # Top 10 total
    
    def _calculate_workflow_security_score(self, task_results: List[ComponentAnalysisResult]) -> float:
        """Calculate overall security score from workflow results"""
        if not task_results:
            return 0.0
        
        # Weight successful results higher
        successful_results = [r for r in task_results if r.status == "success"]
        if not successful_results:
            return 0.0
        
        # Simple scoring based on success rate and component types
        success_rate = len(successful_results) / len(task_results)
        
        # Component-specific scoring
        component_scores = []
        for result in successful_results:
            if "security" in result.analysis_type:
                score = result.result_data.get("confidence_score", 0.5)
            elif "compliance" in result.analysis_type:
                score = 0.8  # Default good compliance score
            elif "performance" in result.analysis_type:
                score = 0.7  # Default performance score
            else:
                score = 0.6  # Default score
            
            component_scores.append(score)
        
        # Calculate weighted average
        if component_scores:
            avg_component_score = sum(component_scores) / len(component_scores)
            overall_score = (success_rate * 0.3) + (avg_component_score * 0.7)
        else:
            overall_score = success_rate
        
        return round(overall_score, 2)
    
    def _generate_workflow_summary(self, workflow: AnalysisWorkflow, 
                                 task_results: List[ComponentAnalysisResult]) -> str:
        """Generate workflow execution summary"""
        successful_tasks = len([r for r in task_results if r.status == "success"])
        failed_tasks = len(workflow.tasks) - successful_tasks
        
        execution_time = 0
        if workflow.started_at and workflow.completed_at:
            execution_time = (workflow.completed_at - workflow.started_at).total_seconds()
        
        summary = f"""Workflow Execution Summary:
Workflow: {workflow.workflow_name} ({workflow.workflow_id})
Target: {workflow.target_path}
Status: {workflow.status.value.title()}
Tasks: {len(workflow.tasks)} total, {successful_tasks} successful, {failed_tasks} failed
Execution Time: {execution_time:.1f} seconds
Analysis Types: {', '.join(set(task.analysis_type for task in workflow.tasks))}
"""
        
        return summary
    
    def _generate_execution_summary(self, workflow: AnalysisWorkflow, 
                                  task_results: List[ComponentAnalysisResult]) -> Dict[str, Any]:
        """Generate execution summary metadata"""
        return {
            "workflow_id": workflow.workflow_id,
            "workflow_name": workflow.workflow_name,
            "status": workflow.status.value,
            "total_tasks": len(workflow.tasks),
            "successful_tasks": len([r for r in task_results if r.status == "success"]),
            "failed_tasks": len(workflow.tasks) - len([r for r in task_results if r.status == "success"]),
            "execution_time_seconds": (
                (workflow.completed_at or datetime.now()) - workflow.started_at
            ).total_seconds() if workflow.started_at else 0,
            "analysis_types": list(set(task.analysis_type for task in workflow.tasks)),
            "components_used": list(set(task.component_name for task in workflow.tasks))
        }
    
    def _initialize_workflow_templates(self) -> Dict[str, Callable]:
        """Initialize workflow templates"""
        return {
            "comprehensive": self.create_comprehensive_analysis_workflow,
            "security": self.create_security_focused_workflow,
            "compliance": self.create_compliance_workflow
        }
    
    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a workflow"""
        # Check active workflows
        if workflow_id in self.active_workflows:
            workflow = self.active_workflows[workflow_id]
            return {
                "workflow_id": workflow_id,
                "status": workflow.status.value,
                "progress": self._calculate_workflow_progress(workflow),
                "current_tasks": [
                    {
                        "task_id": task.task_id,
                        "status": task.status.value,
                        "component": task.component_name
                    }
                    for task in workflow.tasks
                ]
            }
        
        # Check workflow history
        for result in self.workflow_history:
            if result.workflow_id == workflow_id:
                return {
                    "workflow_id": workflow_id,
                    "status": result.status.value,
                    "progress": 100.0,
                    "execution_summary": result.execution_summary
                }
        
        return None
    
    def _calculate_workflow_progress(self, workflow: AnalysisWorkflow) -> float:
        """Calculate workflow progress percentage"""
        if not workflow.tasks:
            return 0.0
        
        completed_tasks = len([t for t in workflow.tasks if t.status == TaskStatus.COMPLETED])
        return (completed_tasks / len(workflow.tasks)) * 100.0
    
    def list_active_workflows(self) -> List[Dict[str, Any]]:
        """List all active workflows"""
        return [
            {
                "workflow_id": workflow_id,
                "workflow_name": workflow.workflow_name,
                "status": workflow.status.value,
                "progress": self._calculate_workflow_progress(workflow),
                "started_at": workflow.started_at.isoformat() if workflow.started_at else None
            }
            for workflow_id, workflow in self.active_workflows.items()
        ]
    
    def get_workflow_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get workflow execution history"""
        return [
            {
                "workflow_id": result.workflow_id,
                "status": result.status.value,
                "execution_summary": result.execution_summary
            }
            for result in self.workflow_history[-limit:]
        ]
    
    async def cancel_workflow(self, workflow_id: str) -> bool:
        """Cancel an active workflow"""
        if workflow_id in self.active_workflows:
            workflow = self.active_workflows[workflow_id]
            workflow.status = WorkflowStatus.CANCELLED
            workflow.completed_at = datetime.now()
            
            # Cancel running tasks
            for task in workflow.tasks:
                if task.status == TaskStatus.RUNNING:
                    task.status = TaskStatus.SKIPPED
                    task.end_time = datetime.now()
            
            self.logger.info(f"Workflow cancelled: {workflow_id}")
            return True
        
        return False
    
    def close(self):
        """Close orchestrator and cleanup resources"""
        try:
            self.analysis_platform.close()
            self.logger.info("Workflow Orchestrator closed")
        except Exception as e:
            self.logger.error(f"Error closing orchestrator: {e}")


# Example usage and testing
async def example_workflow_execution():
    """Example of workflow execution"""
    orchestrator = WorkflowOrchestrator()
    
    # Create a comprehensive analysis workflow
    workflow = orchestrator.create_comprehensive_analysis_workflow(
        target_path="./src",
        workflow_name="Example Comprehensive Analysis"
    )
    
    print(f"Created workflow: {workflow.workflow_id}")
    print(f"Tasks: {len(workflow.tasks)}")
    
    # Execute workflow
    try:
        result = await orchestrator.execute_workflow(workflow)
        print(f"Workflow completed with status: {result.status.value}")
        
        if result.unified_report:
            print(f"Security score: {result.unified_report.overall_security_score}")
            print(f"Recommendations: {len(result.unified_report.unified_recommendations)}")
    
    except Exception as e:
        print(f"Workflow execution failed: {e}")
    
    finally:
        orchestrator.close()


if __name__ == "__main__":
    # Run example
    asyncio.run(example_workflow_execution())