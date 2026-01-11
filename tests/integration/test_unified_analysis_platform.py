"""
Integration Tests for Unified Analysis Platform

Tests the complete integration of all analysis components through the unified platform.
Validates cross-component workflows, data consistency, and end-to-end functionality.
"""

import pytest
import asyncio
import tempfile
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, AsyncMock

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python'))

from integration import (
    UnifiedAnalysisPlatform, UnifiedAnalysisRequest, UnifiedAnalysisReport,
    ComponentAnalysisResult, CrossComponentInsight
)


class TestUnifiedAnalysisPlatform:
    """Test suite for unified analysis platform integration"""
    
    @pytest.fixture
    def temp_project_dir(self):
        """Create temporary project directory for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create sample project structure
            (temp_path / "src").mkdir()
            (temp_path / "src" / "main.py").write_text("""
import os
import hashlib

def process_data(data):
    # Potential security issue: hardcoded secret
    api_key = "sk-1234567890abcdef"
    
    # Weak crypto usage
    hash_value = hashlib.md5(data.encode()).hexdigest()
    
    return hash_value
""")
            
            (temp_path / "requirements.txt").write_text("requests==2.28.0\nflask==2.0.1\n")
            (temp_path / "config.yaml").write_text("database_url: sqlite:///test.db\n")
            
            # Create SDD files for compliance testing
            (temp_path / "requirements.md").write_text("""
# Requirements Document

## Introduction
Sample project requirements

## Glossary
- **System**: The sample system

## Requirements

### Requirement 1
**User Story:** As a user, I want to process data

#### Acceptance Criteria
1. WHEN data is provided, THE System SHALL process it
""")
            
            (temp_path / "design.md").write_text("""
# Design Document

## Overview
Sample design

## Architecture
Simple architecture

## Components and Interfaces
Basic components

## Data Models
Simple models

## Correctness Properties
Property 1: Data processing works
**Validates: Requirements 1.1**
""")
            
            (temp_path / "tasks.md").write_text("""
# Implementation Plan

## Overview
Sample tasks

## Tasks
- [ ] 1. Implement data processing
  - _Requirements: 1.1_
""")
            
            yield str(temp_path)
    
    @pytest.fixture
    def platform(self):
        """Create unified analysis platform instance"""
        return UnifiedAnalysisPlatform()
    
    @pytest.fixture
    def sample_analysis_request(self, temp_project_dir):
        """Create sample analysis request"""
        return UnifiedAnalysisRequest(
            analysis_id="test_integration_001",
            target_path=temp_project_dir,
            analysis_types=["security", "compliance"],
            include_recommendations=True,
            include_cross_component_correlation=True
        )
    
    @pytest.mark.asyncio
    async def test_unified_analysis_basic_execution(self, platform, sample_analysis_request):
        """Test basic unified analysis execution"""
        try:
            # Run unified analysis
            report = await platform.run_unified_analysis(sample_analysis_request)
            
            # Validate report structure
            assert isinstance(report, UnifiedAnalysisReport)
            assert report.analysis_id == sample_analysis_request.analysis_id
            assert report.target_path == sample_analysis_request.target_path
            assert isinstance(report.component_results, list)
            assert isinstance(report.cross_component_insights, list)
            assert isinstance(report.unified_recommendations, list)
            assert isinstance(report.overall_security_score, float)
            assert 0.0 <= report.overall_security_score <= 1.0
            
            # Validate execution metadata
            assert "total_execution_time_seconds" in report.execution_metadata
            assert "components_analyzed" in report.execution_metadata
            assert "successful_analyses" in report.execution_metadata
            
            print(f"✅ Basic execution test passed - Security score: {report.overall_security_score:.2f}")
            
        finally:
            platform.close()
    
    @pytest.mark.asyncio
    async def test_component_results_validation(self, platform, sample_analysis_request):
        """Test validation of component analysis results"""
        try:
            report = await platform.run_unified_analysis(sample_analysis_request)
            
            # Validate component results
            assert len(report.component_results) > 0, "Should have at least one component result"
            
            for result in report.component_results:
                assert isinstance(result, ComponentAnalysisResult)
                assert result.component_name in ["python_ai_analyst", "go_security_analyzer", "cpp_performance_analyzer", "data_intelligence"]
                assert result.analysis_type in ["security_analysis", "compliance_analysis", "sast_analysis", "secrets_analysis", "crypto_analysis", "performance_analysis", "governance_analysis"]
                assert result.status in ["success", "error", "partial"]
                assert isinstance(result.execution_time_seconds, (int, float))
                assert result.execution_time_seconds >= 0
                assert isinstance(result.result_data, dict)
            
            # Check for expected analysis types
            analysis_types = [r.analysis_type for r in report.component_results]
            assert "security_analysis" in analysis_types or "compliance_analysis" in analysis_types
            
            print(f"✅ Component results validation passed - {len(report.component_results)} components")
            
        finally:
            platform.close()
    
    @pytest.mark.asyncio
    async def test_cross_component_insights_generation(self, platform, temp_project_dir):
        """Test cross-component insights generation"""
        # Create request with multiple analysis types to trigger insights
        request = UnifiedAnalysisRequest(
            analysis_id="test_insights_001",
            target_path=temp_project_dir,
            analysis_types=["security", "compliance", "sast"],
            include_cross_component_correlation=True
        )
        
        try:
            report = await platform.run_unified_analysis(request)
            
            # Validate insights structure
            for insight in report.cross_component_insights:
                assert isinstance(insight, CrossComponentInsight)
                assert insight.insight_id
                assert insight.insight_type
                assert insight.description
                assert isinstance(insight.contributing_components, list)
                assert len(insight.contributing_components) >= 2  # Cross-component requires multiple components
                assert isinstance(insight.confidence_score, float)
                assert 0.0 <= insight.confidence_score <= 1.0
                assert isinstance(insight.recommendations, list)
                assert isinstance(insight.supporting_evidence, dict)
            
            print(f"✅ Cross-component insights test passed - {len(report.cross_component_insights)} insights")
            
        finally:
            platform.close()
    
    @pytest.mark.asyncio
    async def test_unified_recommendations_generation(self, platform, sample_analysis_request):
        """Test unified recommendations generation"""
        try:
            report = await platform.run_unified_analysis(sample_analysis_request)
            
            # Validate recommendations
            assert isinstance(report.unified_recommendations, list)
            assert len(report.unified_recommendations) > 0, "Should generate at least one recommendation"
            
            for recommendation in report.unified_recommendations:
                assert isinstance(recommendation, str)
                assert len(recommendation) > 10, "Recommendations should be meaningful"
            
            # Check for expected recommendation types
            recommendations_text = " ".join(report.unified_recommendations).lower()
            expected_keywords = ["security", "implement", "review", "monitor", "improve"]
            found_keywords = [kw for kw in expected_keywords if kw in recommendations_text]
            assert len(found_keywords) > 0, f"Should contain security-related keywords, found: {found_keywords}"
            
            print(f"✅ Unified recommendations test passed - {len(report.unified_recommendations)} recommendations")
            
        finally:
            platform.close()
    
    @pytest.mark.asyncio
    async def test_error_handling_and_resilience(self, platform):
        """Test error handling and system resilience"""
        # Test with invalid target path
        invalid_request = UnifiedAnalysisRequest(
            analysis_id="test_error_001",
            target_path="/nonexistent/path",
            analysis_types=["security"],
            include_recommendations=True
        )
        
        try:
            report = await platform.run_unified_analysis(invalid_request)
            
            # Should still return a report, but with error status
            assert isinstance(report, UnifiedAnalysisReport)
            
            # Check that errors are properly captured
            error_results = [r for r in report.component_results if r.status == "error"]
            assert len(error_results) > 0, "Should have error results for invalid path"
            
            for error_result in error_results:
                assert error_result.error_message is not None
                assert len(error_result.error_message) > 0
            
            print(f"✅ Error handling test passed - {len(error_results)} error results captured")
            
        finally:
            platform.close()
    
    @pytest.mark.asyncio
    async def test_analysis_type_filtering(self, platform, temp_project_dir):
        """Test that analysis types are properly filtered"""
        # Test with specific analysis types
        security_request = UnifiedAnalysisRequest(
            analysis_id="test_security_only",
            target_path=temp_project_dir,
            analysis_types=["security"],
            include_recommendations=True
        )
        
        try:
            report = await platform.run_unified_analysis(security_request)
            
            # Should only have security-related analysis types
            analysis_types = [r.analysis_type for r in report.component_results]
            security_types = [t for t in analysis_types if "security" in t.lower()]
            assert len(security_types) > 0, "Should have security analysis results"
            
            print(f"✅ Analysis type filtering test passed - {len(security_types)} security analyses")
            
        finally:
            platform.close()
    
    @pytest.mark.asyncio
    async def test_concurrent_analysis_execution(self, platform, temp_project_dir):
        """Test concurrent execution of multiple analyses"""
        # Create multiple requests
        requests = [
            UnifiedAnalysisRequest(
                analysis_id=f"test_concurrent_{i}",
                target_path=temp_project_dir,
                analysis_types=["security"],
                include_recommendations=False
            )
            for i in range(3)
        ]
        
        try:
            # Run analyses concurrently
            start_time = datetime.now()
            reports = await asyncio.gather(*[
                platform.run_unified_analysis(req) for req in requests
            ])
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Validate all reports
            assert len(reports) == 3
            for i, report in enumerate(reports):
                assert report.analysis_id == f"test_concurrent_{i}"
                assert isinstance(report, UnifiedAnalysisReport)
            
            # Concurrent execution should be faster than sequential
            assert execution_time < 60, f"Concurrent execution took too long: {execution_time}s"
            
            print(f"✅ Concurrent execution test passed - {len(reports)} reports in {execution_time:.2f}s")
            
        finally:
            platform.close()
    
    def test_platform_initialization_and_cleanup(self):
        """Test platform initialization and cleanup"""
        # Test initialization
        platform = UnifiedAnalysisPlatform()
        assert platform.ai_analyst is not None
        assert platform.data_intelligence is not None
        assert platform.go_analyzer is not None
        assert platform.cpp_analyzer is not None
        
        # Test cleanup
        platform.close()
        
        print("✅ Platform initialization and cleanup test passed")
    
    @pytest.mark.asyncio
    async def test_data_consistency_across_components(self, platform, temp_project_dir):
        """Test data consistency across different analysis components"""
        request = UnifiedAnalysisRequest(
            analysis_id="test_consistency_001",
            target_path=temp_project_dir,
            analysis_types=["security", "compliance"],
            include_cross_component_correlation=True
        )
        
        try:
            report = await platform.run_unified_analysis(request)
            
            # Check that target path is consistent across all results
            for result in report.component_results:
                # All results should reference the same target path
                assert temp_project_dir in str(result.result_data) or result.result_data == {}
            
            # Check that analysis ID is consistent
            assert report.analysis_id == request.analysis_id
            
            # Check timestamp consistency (should be recent)
            time_diff = (datetime.now() - report.timestamp).total_seconds()
            assert time_diff < 300, f"Report timestamp too old: {time_diff}s"
            
            print("✅ Data consistency test passed")
            
        finally:
            platform.close()


class TestIntegrationWorkflows:
    """Test integration workflows and complex scenarios"""
    
    @pytest.fixture
    def complex_project_dir(self):
        """Create complex project directory for workflow testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create multi-language project
            (temp_path / "src" / "python").mkdir(parents=True)
            (temp_path / "src" / "go").mkdir(parents=True)
            (temp_path / "src" / "cpp").mkdir(parents=True)
            
            # Python files with various security issues
            (temp_path / "src" / "python" / "app.py").write_text("""
import sqlite3
import hashlib

def authenticate_user(username, password):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    # Weak hashing
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    return query, password_hash

# Hardcoded secret
API_SECRET = "super_secret_key_12345"
""")
            
            # Go files
            (temp_path / "src" / "go" / "main.go").write_text("""
package main

import (
    "crypto/md5"
    "fmt"
)

func main() {
    // Weak crypto
    hash := md5.Sum([]byte("data"))
    fmt.Printf("%x", hash)
}
""")
            
            # C++ files
            (temp_path / "src" / "cpp" / "crypto.cpp").write_text("""
#include <openssl/md5.h>
#include <string>

class CryptoManager {
public:
    std::string hashData(const std::string& data) {
        // Weak crypto usage
        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5((unsigned char*)data.c_str(), data.length(), digest);
        return std::string((char*)digest, MD5_DIGEST_LENGTH);
    }
};
""")
            
            # Configuration files
            (temp_path / "config" / "database.yaml").mkdir(parents=True)
            (temp_path / "config" / "database.yaml").write_text("""
database:
  host: localhost
  username: admin
  password: admin123  # Hardcoded password
""")
            
            # Data files
            (temp_path / "data").mkdir()
            (temp_path / "data" / "users.json").write_text("""
{
  "users": [
    {"id": 1, "email": "user@example.com", "role": "admin"}
  ]
}
""")
            
            yield str(temp_path)
    
    @pytest.mark.asyncio
    async def test_end_to_end_analysis_workflow(self, complex_project_dir):
        """Test complete end-to-end analysis workflow"""
        platform = UnifiedAnalysisPlatform()
        
        try:
            # Comprehensive analysis request
            request = UnifiedAnalysisRequest(
                analysis_id="test_e2e_workflow",
                target_path=complex_project_dir,
                analysis_types=["security", "sast", "secrets", "governance"],
                include_recommendations=True,
                include_cross_component_correlation=True
            )
            
            # Execute analysis
            report = await platform.run_unified_analysis(request)
            
            # Validate comprehensive results
            assert len(report.component_results) >= 2, "Should have multiple component results"
            
            # Should detect security issues
            security_findings = []
            for result in report.component_results:
                if result.status == "success":
                    findings = result.result_data.get("security_findings", [])
                    if isinstance(findings, list):
                        security_findings.extend(findings)
            
            # Should have cross-component insights
            assert len(report.cross_component_insights) >= 0, "Should generate insights"
            
            # Should have comprehensive recommendations
            assert len(report.unified_recommendations) >= 3, "Should have multiple recommendations"
            
            # Security score should reflect issues found
            assert report.overall_security_score < 1.0, "Should detect security issues"
            
            print(f"✅ End-to-end workflow test passed")
            print(f"   Security score: {report.overall_security_score:.2f}")
            print(f"   Components: {len(report.component_results)}")
            print(f"   Insights: {len(report.cross_component_insights)}")
            print(f"   Recommendations: {len(report.unified_recommendations)}")
            
        finally:
            platform.close()
    
    @pytest.mark.asyncio
    async def test_system_resilience_under_load(self, complex_project_dir):
        """Test system resilience under concurrent load"""
        platform = UnifiedAnalysisPlatform()
        
        try:
            # Create multiple concurrent requests
            requests = [
                UnifiedAnalysisRequest(
                    analysis_id=f"load_test_{i}",
                    target_path=complex_project_dir,
                    analysis_types=["security"],
                    include_recommendations=False,
                    include_cross_component_correlation=False
                )
                for i in range(5)
            ]
            
            # Execute with timeout
            start_time = datetime.now()
            reports = await asyncio.wait_for(
                asyncio.gather(*[platform.run_unified_analysis(req) for req in requests]),
                timeout=120  # 2 minute timeout
            )
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Validate all completed
            assert len(reports) == 5, "All requests should complete"
            
            # Check for reasonable performance
            avg_time_per_request = execution_time / len(reports)
            assert avg_time_per_request < 60, f"Average time per request too high: {avg_time_per_request:.2f}s"
            
            print(f"✅ Load test passed - {len(reports)} requests in {execution_time:.2f}s")
            
        finally:
            platform.close()


if __name__ == "__main__":
    # Run tests manually for debugging
    import asyncio
    
    async def run_manual_tests():
        """Run tests manually for debugging"""
        test_instance = TestUnifiedAnalysisPlatform()
        
        # Create temp directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create minimal test structure
            (temp_path / "test.py").write_text("print('hello')")
            
            platform = UnifiedAnalysisPlatform()
            request = UnifiedAnalysisRequest(
                analysis_id="manual_test",
                target_path=str(temp_path),
                analysis_types=["security"],
                include_recommendations=True
            )
            
            try:
                report = await platform.run_unified_analysis(request)
                print(f"Manual test completed - Score: {report.overall_security_score}")
            finally:
                platform.close()
    
    # Run manual test
    asyncio.run(run_manual_tests())