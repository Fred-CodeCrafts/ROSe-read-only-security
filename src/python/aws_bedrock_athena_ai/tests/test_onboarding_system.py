"""
Tests for the onboarding and demonstration system.

These tests verify that the quick-start, tutorial, and demo scenario
systems work correctly for new user onboarding.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch

from aws_bedrock_athena_ai.onboarding import (
    QuickStartManager, TutorialSystem, DemoScenarios
)
from aws_bedrock_athena_ai.onboarding.models import (
    DataFormat, OnboardingStage, TutorialType
)
from aws_bedrock_athena_ai.onboarding.format_detector import DataFormatDetector
from aws_bedrock_athena_ai.onboarding.sample_data import SampleDataGenerator


class TestQuickStartManager:
    """Test the quick-start onboarding manager"""
    
    @patch('aws_bedrock_athena_ai.onboarding.quick_start.create_aws_clients')
    def test_start_onboarding_session(self, mock_clients):
        """Test starting a new onboarding session"""
        # Mock AWS clients
        mock_clients.return_value = Mock()
        
        manager = QuickStartManager()
        session = manager.start_onboarding_session("test_user")
        
        assert session.progress.user_id == "test_user"
        assert session.progress.current_stage == OnboardingStage.WELCOME
        assert len(session.progress.stages_completed) == 0
        assert session.session_id.startswith("onboard_test_user_")
    
    @patch('aws_bedrock_athena_ai.onboarding.quick_start.create_aws_clients')
    def test_generate_sample_data_for_demo(self, mock_clients):
        """Test generating sample data for demonstration"""
        # Mock AWS clients and S3 operations
        mock_client_manager = Mock()
        mock_client_manager.s3.put_object.return_value = {}
        mock_clients.return_value = mock_client_manager
        
        manager = QuickStartManager()
        session = manager.start_onboarding_session("test_user")
        
        uploaded_file = manager.generate_sample_data_for_demo(
            session,
            data_format=DataFormat.JSON,
            record_count=100
        )
        
        assert uploaded_file.detected_format == DataFormat.JSON
        assert uploaded_file.confidence_score > 0.8  # High confidence for generated data
        assert uploaded_file.file_size_bytes > 0
        assert len(session.progress.uploaded_files) == 1
        assert OnboardingStage.DATA_UPLOAD in session.progress.stages_completed
        assert OnboardingStage.FORMAT_DETECTION in session.progress.stages_completed
    
    @patch('aws_bedrock_athena_ai.onboarding.quick_start.create_aws_clients')
    def test_perform_quick_analysis(self, mock_clients):
        """Test performing quick security analysis"""
        # Mock AWS clients
        mock_clients.return_value = Mock()
        
        manager = QuickStartManager()
        session = manager.start_onboarding_session("test_user")
        
        # Generate sample data first
        manager.generate_sample_data_for_demo(session, DataFormat.JSON, 100)
        
        # Perform analysis
        analysis_result = manager.perform_quick_analysis(session)
        
        assert analysis_result.analysis_id.startswith("sample_analysis_")
        assert len(analysis_result.files_analyzed) == 1
        assert len(analysis_result.key_findings) > 0
        assert len(analysis_result.critical_issues) > 0
        assert 0 <= analysis_result.security_score <= 100
        assert len(analysis_result.recommendations) > 0
        assert analysis_result.analysis_duration_seconds >= 0


class TestDataFormatDetector:
    """Test the automatic data format detection"""
    
    def test_detect_json_format(self):
        """Test detecting JSON format"""
        detector = DataFormatDetector()
        
        json_content = '''{"timestamp": "2024-01-01T10:00:00Z", "event": "login", "user": "admin"}
{"timestamp": "2024-01-01T10:01:00Z", "event": "logout", "user": "admin"}'''
        
        result = detector.detect_format(json_content, "security.json")
        
        assert result.detected_format == DataFormat.JSON
        assert result.confidence_score > 0.5
        assert len(result.sample_data) > 0
        assert "json" in result.schema_preview["format"]
    
    def test_detect_csv_format(self):
        """Test detecting CSV format"""
        detector = DataFormatDetector()
        
        csv_content = '''timestamp,event,user,result
2024-01-01T10:00:00Z,login,admin,success
2024-01-01T10:01:00Z,logout,admin,success'''
        
        result = detector.detect_format(csv_content, "security.csv")
        
        assert result.detected_format == DataFormat.CSV
        assert result.confidence_score > 0.5
        assert len(result.sample_data) > 0
        assert "csv" in result.schema_preview["format"]
    
    def test_detect_cloudtrail_format(self):
        """Test detecting CloudTrail format"""
        detector = DataFormatDetector()
        
        cloudtrail_content = '''{"eventVersion":"1.08","userIdentity":{"type":"IAMUser"},"eventTime":"2024-01-01T10:00:00Z","eventSource":"iam.amazonaws.com","eventName":"CreateUser","awsRegion":"us-east-1","sourceIPAddress":"192.168.1.1"}'''
        
        result = detector.detect_format(cloudtrail_content, "cloudtrail.json")
        
        assert result.detected_format == DataFormat.CLOUDTRAIL
        assert result.confidence_score > 0.5
        assert "cloudtrail" in result.schema_preview["format"]


class TestSampleDataGenerator:
    """Test the sample data generator"""
    
    def test_generate_json_logs(self):
        """Test generating JSON format logs"""
        generator = SampleDataGenerator()
        
        sample_data = generator.generate_sample_dataset(
            format_type=DataFormat.JSON,
            record_count=10,
            include_threats=True
        )
        
        lines = sample_data.strip().split('\n')
        assert len(lines) == 10
        
        # Verify each line is valid JSON
        import json
        for line in lines:
            data = json.loads(line)
            assert "timestamp" in data
            assert "event_type" in data
            assert "user" in data
    
    def test_generate_csv_logs(self):
        """Test generating CSV format logs"""
        generator = SampleDataGenerator()
        
        sample_data = generator.generate_sample_dataset(
            format_type=DataFormat.CSV,
            record_count=10,
            include_threats=False
        )
        
        lines = sample_data.strip().split('\n')
        assert len(lines) == 11  # 10 data rows + 1 header
        
        # Verify header
        header = lines[0]
        assert "timestamp" in header
        assert "event_type" in header
        assert "user" in header
    
    def test_generate_critical_issues_sample(self):
        """Test generating sample critical issues"""
        generator = SampleDataGenerator()
        
        issues = generator.generate_critical_issues_sample()
        
        assert len(issues) > 0
        for issue in issues:
            assert "issue_id" in issue
            assert "title" in issue
            assert "severity" in issue
            assert "description" in issue
            assert "recommendation" in issue


class TestTutorialSystem:
    """Test the tutorial system"""
    
    def test_get_available_tutorials(self):
        """Test getting available tutorials"""
        tutorial_system = TutorialSystem()
        
        tutorials = tutorial_system.get_available_tutorials()
        
        assert len(tutorials) > 0
        
        # Check that basic tutorial exists
        basic_tutorials = [t for t in tutorials if t.tutorial_type == TutorialType.BASIC_QUESTIONS]
        assert len(basic_tutorials) > 0
        
        basic_tutorial = basic_tutorials[0]
        assert basic_tutorial.title
        assert basic_tutorial.description
        assert len(basic_tutorial.steps) > 0
    
    def test_start_tutorial(self):
        """Test starting a tutorial"""
        from aws_bedrock_athena_ai.onboarding.models import OnboardingSession, OnboardingProgress
        
        tutorial_system = TutorialSystem()
        
        # Create mock session
        progress = OnboardingProgress(user_id="test_user", current_stage=OnboardingStage.TUTORIAL)
        session = OnboardingSession(session_id="test_session", progress=progress)
        
        # Start basic tutorial
        tutorial = tutorial_system.start_tutorial("basic_questions", session)
        
        assert tutorial.tutorial_id == "basic_questions"
        assert tutorial.started_at is not None
        assert tutorial.completion_percentage == 0.0
        assert session.active_tutorial == tutorial
    
    def test_complete_tutorial_step(self):
        """Test completing a tutorial step"""
        from aws_bedrock_athena_ai.onboarding.models import OnboardingSession, OnboardingProgress
        
        tutorial_system = TutorialSystem()
        
        # Create mock session and start tutorial
        progress = OnboardingProgress(user_id="test_user", current_stage=OnboardingStage.TUTORIAL)
        session = OnboardingSession(session_id="test_session", progress=progress)
        tutorial = tutorial_system.start_tutorial("basic_questions", session)
        
        # Complete first step
        first_step = tutorial.steps[0]
        result = tutorial_system.complete_tutorial_step(
            "basic_questions", 
            first_step.step_id, 
            session
        )
        
        assert result["step_completed"] == first_step.step_id
        assert result["tutorial_progress"] > 0
        assert first_step.completed is True


class TestDemoScenarios:
    """Test the demonstration scenarios"""
    
    def test_get_available_scenarios(self):
        """Test getting available scenarios"""
        scenarios = DemoScenarios()
        
        available_scenarios = scenarios.get_available_scenarios()
        
        assert len(available_scenarios) > 0
        
        # Check that breach detection scenario exists
        breach_scenarios = [s for s in available_scenarios if s.scenario_type == "breach_detection"]
        assert len(breach_scenarios) > 0
        
        breach_scenario = breach_scenarios[0]
        assert breach_scenario.title
        assert breach_scenario.description
        assert len(breach_scenario.key_questions) > 0
        assert len(breach_scenario.expected_insights) > 0
    
    def test_start_scenario(self):
        """Test starting a demonstration scenario"""
        from aws_bedrock_athena_ai.onboarding.models import OnboardingSession, OnboardingProgress
        
        scenarios = DemoScenarios()
        
        # Create mock session
        progress = OnboardingProgress(user_id="test_user", current_stage=OnboardingStage.DEMO_SCENARIOS)
        session = OnboardingSession(session_id="test_session", progress=progress)
        
        # Start breach detection scenario
        scenario_context = scenarios.start_scenario("breach_detection", session)
        
        assert scenario_context["scenario_id"] == "breach_detection"
        assert "title" in scenario_context
        assert "sample_data" in scenario_context
        assert "key_questions" in scenario_context
        assert scenario_context["current_step"] == 0
        assert scenario_context["progress_percentage"] == 0.0
    
    def test_complete_scenario_step(self):
        """Test completing a scenario step"""
        from aws_bedrock_athena_ai.onboarding.models import OnboardingSession, OnboardingProgress
        
        scenarios = DemoScenarios()
        
        # Create mock session and start scenario
        progress = OnboardingProgress(user_id="test_user", current_stage=OnboardingStage.DEMO_SCENARIOS)
        session = OnboardingSession(session_id="test_session", progress=progress)
        scenario_context = scenarios.start_scenario("breach_detection", session)
        
        # Complete first step
        step_result = scenarios.complete_scenario_step(
            scenario_context, 
            0, 
            "Are we being attacked right now?"
        )
        
        assert step_result["step_number"] == 1
        assert "ai_response" in step_result
        assert step_result["progress"] > 0
        assert "scenario_data" in step_result


if __name__ == "__main__":
    pytest.main([__file__])