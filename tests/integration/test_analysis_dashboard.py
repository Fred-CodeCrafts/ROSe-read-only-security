"""
Integration Tests for Analysis Dashboard

Tests dashboard report generation, visualization, and cross-component reporting.
"""

import pytest
import tempfile
import json
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python'))

from integration import (
    AnalysisDashboard, UnifiedAnalysisReport, ComponentAnalysisResult, 
    CrossComponentInsight, create_sample_dashboard_report
)


class TestAnalysisDashboard:
    """Test suite for analysis dashboard"""
    
    @pytest.fixture
    def dashboard(self):
        """Create dashboard instance with temporary output directory"""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield AnalysisDashboard(output_dir=temp_dir)
    
    @pytest.fixture
    def sample_unified_report(self):
        """Create sample unified analysis report for testing"""
        return UnifiedAnalysisReport(
            analysis_id="test_dashboard_001",
            timestamp=datetime.now(),
            target_path="/test/project",
            component_results=[
                ComponentAnalysisResult(
                    component_name="python_ai_analyst",
                    analysis_type="security_analysis",
                    status="success",
                    result_data={
                        "confidence_score": 0.85,
                        "security_findings": [
                            {"type": "hardcoded_secret", "severity": "high"},
                            {"type": "weak_crypto", "severity": "medium"}
                        ],
                        "recommendations": [
                            "Use environment variables for secrets",
                            "Upgrade to stronger cryptographic algorithms"
                        ]
                    },
                    execution_time_seconds=12.5
                ),
                ComponentAnalysisResult(
                    component_name="go_security_analyzer",
                    analysis_type="sast_analysis",
                    status="success",
                    result_data={
                        "findings": [
                            {"rule_id": "secret_detection", "severity": "high", "file": "config.py"},
                            {"rule_id": "sql_injection", "severity": "medium", "file": "db.py"}
                        ],
                        "scan_stats": {"findings_count": 2, "scan_duration": 8.3}
                    },
                    execution_time_seconds=8.3
                ),
                ComponentAnalysisResult(
                    component_name="cpp_performance_analyzer",
                    analysis_type="crypto_analysis",
                    status="error",
                    result_data={},
                    execution_time_seconds=0.5,
                    error_message="C++ analyzer not available"
                )
            ],
            cross_component_insights=[
                CrossComponentInsight(
                    insight_id="security_correlation_001",
                    insight_type="security_validation",
                    description="Multiple components detected hardcoded secrets",
                    contributing_components=["python_ai_analyst", "go_security_analyzer"],
                    confidence_score=0.9,
                    recommendations=[
                        "Implement comprehensive secret management",
                        "Add automated secret scanning to CI/CD"
                    ],
                    supporting_evidence={
                        "ai_findings": 2,
                        "sast_findings": 2,
                        "overlapping_issues": 1
                    }
                )
            ],
            unified_recommendations=[
                "Implement comprehensive secret management system",
                "Upgrade cryptographic implementations",
                "Add automated security scanning to CI/CD pipeline",
                "Regular security training for development team",
                "Implement code review processes for security"
            ],
            overall_security_score=0.72,
            analysis_summary="Analysis completed with 2 successful components and 1 failed component. Found multiple security issues requiring attention.",
            execution_metadata={
                "total_execution_time_seconds": 21.3,
                "components_analyzed": 3,
                "successful_analyses": 2,
                "analysis_types_requested": ["security", "sast", "crypto"]
            }
        )
    
    def test_unified_report_generation(self, dashboard, sample_unified_report):
        """Test unified HTML report generation"""
        # Generate report
        report_path = dashboard.generate_unified_report(sample_unified_report)
        
        # Validate report file
        assert Path(report_path).exists(), "Report file should be created"
        assert report_path.endswith('.html'), "Report should be HTML file"
        
        # Read and validate HTML content
        with open(report_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Check for essential content
        assert sample_unified_report.analysis_id in html_content
        assert sample_unified_report.target_path in html_content
        assert "72%" in html_content  # Security score
        assert "python_ai_analyst" in html_content
        assert "go_security_analyzer" in html_content
        assert "security_validation" in html_content
        
        # Check for recommendations
        for rec in sample_unified_report.unified_recommendations[:3]:
            assert rec in html_content
        
        print(f"✅ Unified report generation test passed - {Path(report_path).name}")
    
    def test_executive_summary_generation(self, dashboard, sample_unified_report):
        """Test executive summary generation"""
        # Generate executive summary
        summary_path = dashboard.generate_executive_summary(sample_unified_report)
        
        # Validate summary file
        assert Path(summary_path).exists(), "Summary file should be created"
        assert summary_path.endswith('.md'), "Summary should be Markdown file"
        
        # Read and validate content
        with open(summary_path, 'r', encoding='utf-8') as f:
            summary_content = f.read()
        
        # Check for essential content
        assert "# Executive Summary" in summary_content
        assert sample_unified_report.analysis_id in summary_content
        assert "72%" in summary_content or "0.72" in summary_content
        assert "## Key Findings" in summary_content
        assert "## Top Recommendations" in summary_content
        
        # Check for component status
        assert "python_ai_analyst" in summary_content
        assert "go_security_analyzer" in summary_content
        
        print(f"✅ Executive summary generation test passed - {Path(summary_path).name}")
    
    def test_correlation_matrix_generation(self, dashboard, sample_unified_report):
        """Test component correlation matrix generation"""
        # Generate correlation matrix
        matrix_path = dashboard.generate_component_correlation_matrix(sample_unified_report)
        
        # Validate matrix file
        assert Path(matrix_path).exists(), "Matrix file should be created"
        assert matrix_path.endswith('.html'), "Matrix should be HTML file"
        
        # Read and validate content
        with open(matrix_path, 'r', encoding='utf-8') as f:
            matrix_content = f.read()
        
        # Check for essential content
        assert "Component Correlation Matrix" in matrix_content
        assert sample_unified_report.analysis_id in matrix_content
        assert "python_ai_analyst" in matrix_content
        assert "go_security_analyzer" in matrix_content
        assert "correlation-high" in matrix_content or "correlation-medium" in matrix_content
        
        print(f"✅ Correlation matrix generation test passed - {Path(matrix_path).name}")
    
    def test_json_report_generation(self, dashboard, sample_unified_report):
        """Test JSON report generation alongside HTML"""
        # Generate unified report (should create both HTML and JSON)
        html_path = dashboard.generate_unified_report(sample_unified_report)
        
        # Check for JSON file
        json_path = html_path.replace('.html', '.json')
        assert Path(json_path).exists(), "JSON report should be created alongside HTML"
        
        # Validate JSON content
        with open(json_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        
        # Check essential fields
        assert json_data["analysis_id"] == sample_unified_report.analysis_id
        assert json_data["target_path"] == sample_unified_report.target_path
        assert json_data["overall_security_score"] == sample_unified_report.overall_security_score
        assert len(json_data["component_results"]) == len(sample_unified_report.component_results)
        assert len(json_data["cross_component_insights"]) == len(sample_unified_report.cross_component_insights)
        
        print(f"✅ JSON report generation test passed - {Path(json_path).name}")
    
    def test_report_with_no_insights(self, dashboard):
        """Test report generation with no cross-component insights"""
        # Create report with no insights
        report_no_insights = UnifiedAnalysisReport(
            analysis_id="test_no_insights",
            timestamp=datetime.now(),
            target_path="/test/simple",
            component_results=[
                ComponentAnalysisResult(
                    component_name="python_ai_analyst",
                    analysis_type="security_analysis",
                    status="success",
                    result_data={"confidence_score": 0.8},
                    execution_time_seconds=5.0
                )
            ],
            cross_component_insights=[],  # No insights
            unified_recommendations=["Basic recommendation"],
            overall_security_score=0.8,
            analysis_summary="Simple analysis with no cross-component insights",
            execution_metadata={"total_execution_time_seconds": 5.0}
        )
        
        # Generate report
        report_path = dashboard.generate_unified_report(report_no_insights)
        
        # Validate report exists and handles empty insights
        assert Path(report_path).exists()
        
        with open(report_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        assert "No cross-component insights generated" in html_content
        
        print("✅ Report with no insights test passed")
    
    def test_report_with_failed_components(self, dashboard):
        """Test report generation with failed components"""
        # Create report with failed components
        report_with_failures = UnifiedAnalysisReport(
            analysis_id="test_failures",
            timestamp=datetime.now(),
            target_path="/test/failures",
            component_results=[
                ComponentAnalysisResult(
                    component_name="python_ai_analyst",
                    analysis_type="security_analysis",
                    status="error",
                    result_data={},
                    execution_time_seconds=1.0,
                    error_message="Analysis failed due to missing dependencies"
                ),
                ComponentAnalysisResult(
                    component_name="go_security_analyzer",
                    analysis_type="sast_analysis",
                    status="error",
                    result_data={},
                    execution_time_seconds=0.5,
                    error_message="SAST tool not available"
                )
            ],
            cross_component_insights=[],
            unified_recommendations=["Fix component dependencies", "Install required tools"],
            overall_security_score=0.0,
            analysis_summary="Analysis failed for all components",
            execution_metadata={"total_execution_time_seconds": 1.5}
        )
        
        # Generate report
        report_path = dashboard.generate_unified_report(report_with_failures)
        
        # Validate report handles failures
        assert Path(report_path).exists()
        
        with open(report_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        assert "status-error" in html_content
        assert "Analysis failed due to missing dependencies" in html_content
        assert "SAST tool not available" in html_content
        
        print("✅ Report with failed components test passed")
    
    def test_dashboard_output_directory_creation(self):
        """Test dashboard output directory creation"""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / "custom_reports"
            
            # Create dashboard with custom output directory
            dashboard = AnalysisDashboard(output_dir=str(output_dir))
            
            # Directory should be created
            assert output_dir.exists(), "Output directory should be created"
            assert output_dir.is_dir(), "Output path should be a directory"
        
        print("✅ Dashboard output directory creation test passed")
    
    def test_sample_dashboard_report_creation(self):
        """Test sample dashboard report creation"""
        # Create sample report
        report_path = create_sample_dashboard_report()
        
        # Validate sample report
        assert Path(report_path).exists(), "Sample report should be created"
        assert report_path.endswith('.html'), "Sample report should be HTML"
        
        # Read and validate content
        with open(report_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        assert "sample_001" in html_content
        assert "Unified Security Analysis Report" in html_content
        assert "security_validation" in html_content
        
        print(f"✅ Sample dashboard report creation test passed - {Path(report_path).name}")
    
    def test_report_security_score_visualization(self, dashboard, sample_unified_report):
        """Test security score visualization in reports"""
        # Test different security scores
        test_scores = [0.9, 0.7, 0.4, 0.1]
        expected_classes = ["high", "medium", "medium", "low"]
        
        for score, expected_class in zip(test_scores, expected_classes):
            # Modify report score
            sample_unified_report.overall_security_score = score
            
            # Generate report
            report_path = dashboard.generate_unified_report(sample_unified_report)
            
            # Check for appropriate CSS class
            with open(report_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            assert f"security-score {expected_class}" in html_content or f"security-score.{expected_class}" in html_content
            assert f"{int(score * 100)}%" in html_content
        
        print("✅ Security score visualization test passed")
    
    def test_large_report_handling(self, dashboard):
        """Test handling of large reports with many components and insights"""
        # Create large report
        large_component_results = []
        for i in range(10):
            large_component_results.append(
                ComponentAnalysisResult(
                    component_name=f"component_{i}",
                    analysis_type=f"analysis_type_{i}",
                    status="success",
                    result_data={"findings": [f"finding_{j}" for j in range(20)]},
                    execution_time_seconds=float(i + 1)
                )
            )
        
        large_insights = []
        for i in range(5):
            large_insights.append(
                CrossComponentInsight(
                    insight_id=f"insight_{i}",
                    insight_type=f"insight_type_{i}",
                    description=f"Large insight description {i} " * 20,
                    contributing_components=[f"component_{i}", f"component_{i+1}"],
                    confidence_score=0.8,
                    recommendations=[f"Recommendation {j}" for j in range(10)],
                    supporting_evidence={f"evidence_{j}": f"value_{j}" for j in range(10)}
                )
            )
        
        large_report = UnifiedAnalysisReport(
            analysis_id="test_large_report",
            timestamp=datetime.now(),
            target_path="/test/large",
            component_results=large_component_results,
            cross_component_insights=large_insights,
            unified_recommendations=[f"Large recommendation {i}" for i in range(20)],
            overall_security_score=0.75,
            analysis_summary="Large analysis report with many components and insights",
            execution_metadata={"total_execution_time_seconds": 100.0}
        )
        
        # Generate report
        report_path = dashboard.generate_unified_report(large_report)
        
        # Validate large report
        assert Path(report_path).exists()
        
        # Check file size is reasonable (not too large)
        file_size = Path(report_path).stat().st_size
        assert file_size < 10 * 1024 * 1024, f"Report file too large: {file_size} bytes"  # Less than 10MB
        
        print(f"✅ Large report handling test passed - File size: {file_size / 1024:.1f} KB")


class TestDashboardIntegration:
    """Test dashboard integration with other components"""
    
    def test_dashboard_with_real_analysis_data(self):
        """Test dashboard with realistic analysis data"""
        # Create realistic analysis report
        realistic_report = UnifiedAnalysisReport(
            analysis_id="realistic_analysis_001",
            timestamp=datetime.now(),
            target_path="/real/project",
            component_results=[
                ComponentAnalysisResult(
                    component_name="python_ai_analyst",
                    analysis_type="security_analysis",
                    status="success",
                    result_data={
                        "repo_structure": {"total_files": 45, "file_types": {".py": 20, ".js": 15, ".yaml": 5}},
                        "security_findings": [
                            {"pattern_id": "SEC_ANTI_PATTERN_HARDCODED_SECRETS", "severity": "high", "file_path": "config.py", "line_range": [15, 15]},
                            {"pattern_id": "SEC_ANTI_PATTERN_WEAK_CRYPTO", "severity": "medium", "file_path": "auth.py", "line_range": [42, 42]}
                        ],
                        "confidence_score": 0.82,
                        "recommendations": ["Use environment variables for secrets", "Upgrade to SHA-256 or better"]
                    },
                    execution_time_seconds=15.3
                ),
                ComponentAnalysisResult(
                    component_name="go_security_analyzer",
                    analysis_type="sast_analysis",
                    status="success",
                    result_data={
                        "findings": [
                            {"rule_id": "hardcoded_password", "severity": "high", "file": "config.py", "line": 15},
                            {"rule_id": "weak_crypto", "severity": "medium", "file": "auth.py", "line": 42}
                        ],
                        "scan_stats": {"findings_count": 2, "scan_duration": 12.1, "rules_executed": 150}
                    },
                    execution_time_seconds=12.1
                )
            ],
            cross_component_insights=[
                CrossComponentInsight(
                    insight_id="security_pattern_correlation",
                    insight_type="security_validation",
                    description="AI analyst and SAST tool both identified hardcoded secrets in config.py",
                    contributing_components=["python_ai_analyst", "go_security_analyzer"],
                    confidence_score=0.95,
                    recommendations=[
                        "High confidence security issue - immediate remediation required",
                        "Implement automated secret scanning in CI/CD"
                    ],
                    supporting_evidence={
                        "ai_findings_count": 2,
                        "sast_findings_count": 2,
                        "overlapping_files": ["config.py", "auth.py"]
                    }
                )
            ],
            unified_recommendations=[
                "Immediately remove hardcoded secrets from config.py",
                "Upgrade cryptographic implementations in auth.py",
                "Implement comprehensive secret management system",
                "Add automated security scanning to CI/CD pipeline",
                "Conduct security code review for all authentication code"
            ],
            overall_security_score=0.68,
            analysis_summary="Security analysis identified critical hardcoded secrets and weak cryptography. Immediate action required for high-severity findings.",
            execution_metadata={
                "total_execution_time_seconds": 27.4,
                "components_analyzed": 2,
                "successful_analyses": 2,
                "analysis_types_requested": ["security", "sast"]
            }
        )
        
        # Generate dashboard
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard = AnalysisDashboard(output_dir=temp_dir)
            
            # Generate all report types
            html_report = dashboard.generate_unified_report(realistic_report)
            exec_summary = dashboard.generate_executive_summary(realistic_report)
            correlation_matrix = dashboard.generate_component_correlation_matrix(realistic_report)
            
            # Validate all reports exist
            assert Path(html_report).exists()
            assert Path(exec_summary).exists()
            assert Path(correlation_matrix).exists()
            
            # Validate content quality
            with open(html_report, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            assert "68%" in html_content  # Security score
            assert "config.py" in html_content  # Specific file mentioned
            assert "hardcoded secrets" in html_content.lower()  # Issue type
            
        print("✅ Dashboard with realistic analysis data test passed")


if __name__ == "__main__":
    # Run tests manually for debugging
    def run_manual_tests():
        """Run tests manually for debugging"""
        # Test sample report creation
        report_path = create_sample_dashboard_report()
        print(f"Sample report created: {report_path}")
        
        # Test dashboard with custom data
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard = AnalysisDashboard(output_dir=temp_dir)
            
            # Create simple test report
            test_report = UnifiedAnalysisReport(
                analysis_id="manual_test",
                timestamp=datetime.now(),
                target_path="/manual/test",
                component_results=[],
                cross_component_insights=[],
                unified_recommendations=["Test recommendation"],
                overall_security_score=0.5,
                analysis_summary="Manual test report",
                execution_metadata={"total_execution_time_seconds": 1.0}
            )
            
            html_path = dashboard.generate_unified_report(test_report)
            print(f"Manual test report created: {html_path}")
    
    # Run manual test
    run_manual_tests()