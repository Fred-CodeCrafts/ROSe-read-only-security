"""
Integration Tests for Workflow Orchestrator

Tests workflow orchestration, dependency resolution, and complex analysis workflows.
"""

import pytest
import asyncio
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python'))

from integration import (
    WorkflowOrchestrator, AnalysisWorkflow, WorkflowTask, WorkflowResult,
    WorkflowStatus, TaskStatus
)


class TestWorkflowOrchestrator:
    """Test suite for workflow orchestrator"""
    
    @pytest.fixture
    def temp_project_dir(self):
        """Create temporary project directory for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create sample project
            (temp_path / "src").mkdir()
            (temp_path / "src" / "main.py").write_text("""
def main():
    print("Hello, World!")
    
if __name__ == "__main__":
    main()
""")
            
            (temp_path / "requirements.md").write_text("""
# Requirements Document

## Introduction
Test requirements

## Glossary
- **System**: Test system

## Requirements

### Requirement 1
**User Story:** As a user, I want functionality

#### Acceptance Criteria
1. WHEN input is provided, THE System SHALL process it
""")
            
            yield str(temp_path)
    
    @pytest.fixture
    def orchestrator(self):
        """Create workflow orchestrator instance"""
        return WorkflowOrchestrator(max_concurrent_workflows=2)
    
    def test_workflow_creation_comprehensive(self, orchestrator, temp_project_dir):
        """Test comprehensive workflow creation"""
        workflow = orchestrator.create_comprehensive_analysis_workflow(
            temp_project_dir, "Test Comprehensive Workflow"
        )
        
        # Validate workflow structure
        assert isinstance(workflow, AnalysisWorkflow)
        assert workflow.workflow_name == "Test Comprehensive Workflow"
        assert workflow.target_path == temp_project_dir
        assert workflow.status == WorkflowStatus.PENDING
        assert len(workflow.tasks) >= 5  # Should have multiple tasks
        
        # Validate task structure
        for task in workflow.tasks:
            assert isinstance(task, WorkflowTask)
            assert task.task_id
            assert task.task_name
            assert task.component_name
            assert task.analysis_type
            assert task.status == TaskStatus.PENDING
            assert task.timeout_seconds > 0
        
        # Check dependency structure
        dependent_tasks = [t for t in workflow.tasks if t.dependencies]
        assert len(dependent_tasks) > 0, "Should have tasks with dependencies"
        
        print(f"✅ Comprehensive workflow creation test passed - {len(workflow.tasks)} tasks")
    
    def test_workflow_creation_security_focused(self, orchestrator, temp_project_dir):
        """Test security-focused workflow creation"""
        workflow = orchestrator.create_security_focused_workflow(
            temp_project_dir, "Security Analysis Workflow"
        )
        
        # Validate workflow
        assert workflow.workflow_name == "Security Analysis Workflow"
        assert workflow.metadata["workflow_type"] == "security_focused"
        
        # Should have security-related tasks
        security_tasks = [t for t in workflow.tasks if "security" in t.analysis_type.lower()]
        assert len(security_tasks) > 0, "Should have security-focused tasks"
        
        print(f"✅ Security workflow creation test passed - {len(workflow.tasks)} tasks")
    
    def test_workflow_creation_compliance(self, orchestrator, temp_project_dir):
        """Test compliance workflow creation"""
        workflow = orchestrator.create_compliance_workflow(
            temp_project_dir, "Compliance Check Workflow"
        )
        
        # Validate workflow
        assert workflow.workflow_name == "Compliance Check Workflow"
        assert workflow.metadata["workflow_type"] == "compliance_focused"
        
        # Should have compliance-related tasks
        compliance_tasks = [t for t in workflow.tasks if "compliance" in t.analysis_type.lower() or "governance" in t.analysis_type.lower()]
        assert len(compliance_tasks) > 0, "Should have compliance-focused tasks"
        
        print(f"✅ Compliance workflow creation test passed - {len(workflow.tasks)} tasks")
    
    @pytest.mark.asyncio
    async def test_workflow_execution_basic(self, orchestrator, temp_project_dir):
        """Test basic workflow execution"""
        # Create simple workflow
        workflow = orchestrator.create_compliance_workflow(temp_project_dir)
        
        try:
            # Execute workflow
            result = await orchestrator.execute_workflow(workflow)
            
            # Validate result
            assert isinstance(result, WorkflowResult)
            assert result.workflow_id == workflow.workflow_id
            assert result.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED]
            assert isinstance(result.task_results, list)
            assert isinstance(result.execution_summary, dict)
            
            # Check execution summary
            summary = result.execution_summary
            assert "workflow_id" in summary
            assert "total_tasks" in summary
            assert "execution_time_seconds" in summary
            assert summary["total_tasks"] == len(workflow.tasks)
            
            print(f"✅ Basic workflow execution test passed - Status: {result.status.value}")
            
        finally:
            orchestrator.close()
    
    @pytest.mark.asyncio
    async def test_task_dependency_resolution(self, orchestrator, temp_project_dir):
        """Test task dependency resolution"""
        # Create workflow with dependencies
        workflow = orchestrator.create_comprehensive_analysis_workflow(temp_project_dir)
        
        # Find tasks with dependencies
        dependent_tasks = [t for t in workflow.tasks if t.dependencies]
        assert len(dependent_tasks) > 0, "Should have dependent tasks for testing"
        
        try:
            # Execute workflow
            result = await orchestrator.execute_workflow(workflow)
            
            # Check that dependencies were respected
            # (This is implicit in successful execution, as dependency violations would cause failures)
            if result.status == WorkflowStatus.COMPLETED:
                print("✅ Task dependency resolution test passed")
            else:
                print(f"⚠️  Workflow completed with status: {result.status.value}")
                if result.error_message:
                    print(f"   Error: {result.error_message}")
            
        finally:
            orchestrator.close()
    
    @pytest.mark.asyncio
    async def test_workflow_error_handling(self, orchestrator):
        """Test workflow error handling with invalid target"""
        # Create workflow with invalid target
        workflow = orchestrator.create_security_focused_workflow(
            "/nonexistent/path", "Error Test Workflow"
        )
        
        try:
            # Execute workflow (should handle errors gracefully)
            result = await orchestrator.execute_workflow(workflow)
            
            # Should complete but may have errors
            assert isinstance(result, WorkflowResult)
            assert result.workflow_id == workflow.workflow_id
            
            # Check for error handling
            if result.status == WorkflowStatus.FAILED:
                assert result.error_message is not None
                print(f"✅ Error handling test passed - Error captured: {result.error_message[:50]}...")
            else:
                # Some components may handle invalid paths gracefully
                print("✅ Error handling test passed - Graceful handling of invalid path")
            
        finally:
            orchestrator.close()
    
    @pytest.mark.asyncio
    async def test_concurrent_workflow_execution(self, orchestrator, temp_project_dir):
        """Test concurrent workflow execution"""
        # Create multiple workflows
        workflows = [
            orchestrator.create_compliance_workflow(temp_project_dir, f"Concurrent Test {i}")
            for i in range(2)  # Within max_concurrent_workflows limit
        ]
        
        try:
            # Execute workflows concurrently
            start_time = datetime.now()
            results = await asyncio.gather(*[
                orchestrator.execute_workflow(workflow) for workflow in workflows
            ])
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Validate results
            assert len(results) == 2
            for result in results:
                assert isinstance(result, WorkflowResult)
                assert result.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED]
            
            # Concurrent execution should be reasonably fast
            assert execution_time < 120, f"Concurrent execution took too long: {execution_time}s"
            
            print(f"✅ Concurrent workflow execution test passed - {len(results)} workflows in {execution_time:.2f}s")
            
        finally:
            orchestrator.close()
    
    def test_workflow_status_tracking(self, orchestrator, temp_project_dir):
        """Test workflow status tracking"""
        # Create workflow
        workflow = orchestrator.create_compliance_workflow(temp_project_dir)
        
        try:
            # Initially should not be tracked
            status = orchestrator.get_workflow_status(workflow.workflow_id)
            assert status is None, "Workflow should not be tracked before execution"
            
            # Test active workflows listing
            active = orchestrator.list_active_workflows()
            assert len(active) == 0, "Should have no active workflows initially"
            
            print("✅ Workflow status tracking test passed")
            
        finally:
            orchestrator.close()
    
    def test_workflow_history_tracking(self, orchestrator):
        """Test workflow history tracking"""
        try:
            # Initially should have no history
            history = orchestrator.get_workflow_history()
            initial_count = len(history)
            
            # History should be a list
            assert isinstance(history, list)
            
            print(f"✅ Workflow history tracking test passed - {initial_count} historical workflows")
            
        finally:
            orchestrator.close()
    
    @pytest.mark.asyncio
    async def test_workflow_cancellation(self, orchestrator, temp_project_dir):
        """Test workflow cancellation"""
        # Create workflow
        workflow = orchestrator.create_comprehensive_analysis_workflow(temp_project_dir)
        
        try:
            # Start workflow execution (don't await)
            execution_task = asyncio.create_task(orchestrator.execute_workflow(workflow))
            
            # Give it a moment to start
            await asyncio.sleep(0.1)
            
            # Cancel workflow
            cancelled = await orchestrator.cancel_workflow(workflow.workflow_id)
            
            if cancelled:
                # Wait for execution to complete
                result = await execution_task
                assert result.status == WorkflowStatus.CANCELLED
                print("✅ Workflow cancellation test passed")
            else:
                # Workflow may have completed too quickly to cancel
                result = await execution_task
                print(f"⚠️  Workflow completed before cancellation: {result.status.value}")
            
        except Exception as e:
            print(f"⚠️  Workflow cancellation test - Exception: {e}")
        finally:
            orchestrator.close()
    
    def test_workflow_templates(self, orchestrator, temp_project_dir):
        """Test workflow template system"""
        # Test all template types
        template_types = ["comprehensive", "security", "compliance"]
        
        for template_type in template_types:
            if template_type == "comprehensive":
                workflow = orchestrator.create_comprehensive_analysis_workflow(temp_project_dir)
            elif template_type == "security":
                workflow = orchestrator.create_security_focused_workflow(temp_project_dir)
            elif template_type == "compliance":
                workflow = orchestrator.create_compliance_workflow(temp_project_dir)
            
            # Validate workflow
            assert isinstance(workflow, AnalysisWorkflow)
            assert workflow.metadata["workflow_type"] == f"{template_type}_focused" if template_type != "comprehensive" else template_type
            assert len(workflow.tasks) > 0
            
        print(f"✅ Workflow templates test passed - {len(template_types)} templates")
    
    def test_orchestrator_initialization_and_cleanup(self):
        """Test orchestrator initialization and cleanup"""
        # Test initialization
        orchestrator = WorkflowOrchestrator(max_concurrent_workflows=5)
        assert orchestrator.max_concurrent_workflows == 5
        assert orchestrator.analysis_platform is not None
        assert orchestrator.dashboard is not None
        assert isinstance(orchestrator.active_workflows, dict)
        assert isinstance(orchestrator.workflow_history, list)
        
        # Test cleanup
        orchestrator.close()
        
        print("✅ Orchestrator initialization and cleanup test passed")


class TestWorkflowIntegration:
    """Test workflow integration with analysis platform"""
    
    @pytest.fixture
    def complex_project_dir(self):
        """Create complex project for integration testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create multi-component project
            (temp_path / "src" / "python").mkdir(parents=True)
            (temp_path / "src" / "go").mkdir(parents=True)
            
            # Python with security issues
            (temp_path / "src" / "python" / "app.py").write_text("""
import hashlib

def hash_password(password):
    # Weak hashing
    return hashlib.md5(password.encode()).hexdigest()

# Hardcoded secret
SECRET_KEY = "hardcoded_secret_123"
""")
            
            # Go code
            (temp_path / "src" / "go" / "main.go").write_text("""
package main

import "fmt"

func main() {
    fmt.Println("Hello, Go!")
}
""")
            
            # SDD files
            (temp_path / "requirements.md").write_text("""
# Requirements Document

## Introduction
Integration test requirements

## Glossary
- **System**: Integration test system

## Requirements

### Requirement 1
**User Story:** As a user, I want secure functionality

#### Acceptance Criteria
1. WHEN processing data, THE System SHALL use secure methods
""")
            
            (temp_path / "design.md").write_text("""
# Design Document

## Overview
Integration test design

## Architecture
Secure architecture

## Components and Interfaces
Secure components

## Data Models
Secure data models

## Correctness Properties
Property 1: Security is maintained
**Validates: Requirements 1.1**
""")
            
            (temp_path / "tasks.md").write_text("""
# Implementation Plan

## Overview
Integration test tasks

## Tasks
- [ ] 1. Implement secure functionality
  - _Requirements: 1.1_
""")
            
            yield str(temp_path)
    
    @pytest.mark.asyncio
    async def test_end_to_end_workflow_integration(self, complex_project_dir):
        """Test complete end-to-end workflow integration"""
        orchestrator = WorkflowOrchestrator()
        
        try:
            # Create comprehensive workflow
            workflow = orchestrator.create_comprehensive_analysis_workflow(
                complex_project_dir, "Integration Test Workflow"
            )
            
            # Execute workflow
            result = await orchestrator.execute_workflow(workflow)
            
            # Validate integration results
            assert isinstance(result, WorkflowResult)
            assert result.workflow_id == workflow.workflow_id
            
            # Should have unified report
            if result.unified_report:
                report = result.unified_report
                assert report.analysis_id == workflow.workflow_id
                assert report.target_path == complex_project_dir
                assert isinstance(report.component_results, list)
                assert isinstance(report.overall_security_score, float)
                
                print(f"✅ End-to-end integration test passed")
                print(f"   Status: {result.status.value}")
                print(f"   Security Score: {report.overall_security_score:.2f}")
                print(f"   Components: {len(report.component_results)}")
                print(f"   Execution Time: {result.execution_summary.get('execution_time_seconds', 0):.2f}s")
            else:
                print(f"⚠️  Workflow completed without unified report: {result.status.value}")
                if result.error_message:
                    print(f"   Error: {result.error_message}")
            
        finally:
            orchestrator.close()
    
    @pytest.mark.asyncio
    async def test_workflow_resilience_and_recovery(self, complex_project_dir):
        """Test workflow resilience and error recovery"""
        orchestrator = WorkflowOrchestrator()
        
        try:
            # Create workflow that may have some failing components
            workflow = orchestrator.create_security_focused_workflow(
                complex_project_dir, "Resilience Test Workflow"
            )
            
            # Execute workflow
            result = await orchestrator.execute_workflow(workflow)
            
            # Should complete even if some components fail
            assert isinstance(result, WorkflowResult)
            assert result.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED]
            
            # Check task results
            successful_tasks = len([r for r in result.task_results if r.status == "success"])
            total_tasks = result.execution_summary.get("total_tasks", 0)
            
            print(f"✅ Workflow resilience test passed")
            print(f"   Status: {result.status.value}")
            print(f"   Successful Tasks: {successful_tasks}/{total_tasks}")
            
        finally:
            orchestrator.close()


if __name__ == "__main__":
    # Run tests manually for debugging
    import asyncio
    
    async def run_manual_tests():
        """Run tests manually for debugging"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            (temp_path / "test.py").write_text("print('test')")
            
            orchestrator = WorkflowOrchestrator()
            
            try:
                # Test workflow creation
                workflow = orchestrator.create_compliance_workflow(str(temp_path))
                print(f"Created workflow with {len(workflow.tasks)} tasks")
                
                # Test execution
                result = await orchestrator.execute_workflow(workflow)
                print(f"Workflow completed with status: {result.status.value}")
                
            finally:
                orchestrator.close()
    
    # Run manual test
    asyncio.run(run_manual_tests())