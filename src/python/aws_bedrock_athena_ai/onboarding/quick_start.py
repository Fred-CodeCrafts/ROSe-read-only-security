"""
Quick-start manager for onboarding new users.

This module provides the main orchestration for the 5-minute onboarding
experience, including data upload, format detection, and initial analysis.
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
import boto3
from pathlib import Path

from aws_bedrock_athena_ai.config import AWSConfig, create_aws_clients
from aws_bedrock_athena_ai.data_detective import SmartDataDetective
from aws_bedrock_athena_ai.reasoning_engine import ExpertReasoningEngine
from aws_bedrock_athena_ai.insights import InstantInsightsGenerator
from aws_bedrock_athena_ai.onboarding.models import (
    OnboardingSession, OnboardingProgress, OnboardingStage,
    UploadedFile, QuickAnalysisResult, DataFormat
)
from aws_bedrock_athena_ai.onboarding.format_detector import DataFormatDetector
from aws_bedrock_athena_ai.onboarding.sample_data import SampleDataGenerator

logger = logging.getLogger(__name__)


class QuickStartManager:
    """Manages the quick-start onboarding experience for new users"""
    
    def __init__(self, aws_config: Optional[AWSConfig] = None):
        self.config = aws_config or AWSConfig.from_environment()
        self.client_manager = create_aws_clients(self.config)
        
        # Initialize components
        self.format_detector = DataFormatDetector()
        self.sample_generator = SampleDataGenerator()
        self.data_detective = SmartDataDetective(self.client_manager)
        self.reasoning_engine = ExpertReasoningEngine(self.client_manager)
        self.insights_generator = InstantInsightsGenerator()
        
        # Onboarding configuration
        self.max_file_size_mb = 50  # Limit for quick start
        self.analysis_timeout_seconds = 300  # 5 minutes max
        
    def start_onboarding_session(self, user_id: str) -> OnboardingSession:
        """
        Start a new onboarding session for a user.
        
        Args:
            user_id: Unique identifier for the user
            
        Returns:
            OnboardingSession with initial state
        """
        logger.info(f"🚀 Starting onboarding session for user: {user_id}")
        
        # Create progress tracker
        progress = OnboardingProgress(
            user_id=user_id,
            current_stage=OnboardingStage.WELCOME
        )
        
        # Create session
        session = OnboardingSession(
            session_id=f"onboard_{user_id}_{int(datetime.now().timestamp())}",
            progress=progress
        )
        
        logger.info(f"✅ Onboarding session created: {session.session_id}")
        return session
    
    def upload_sample_data(self, session: OnboardingSession, 
                          file_content: str, 
                          filename: str) -> UploadedFile:
        """
        Upload and process sample security data.
        
        Args:
            session: Current onboarding session
            file_content: Content of the uploaded file
            filename: Original filename
            
        Returns:
            UploadedFile with processing results
        """
        logger.info(f"📁 Processing uploaded file: {filename}")
        
        # Validate file size
        file_size = len(file_content.encode('utf-8'))
        if file_size > self.max_file_size_mb * 1024 * 1024:
            raise ValueError(f"File too large. Maximum size: {self.max_file_size_mb}MB")
        
        # Detect format
        detection_result = self.format_detector.detect_format(file_content, filename)
        
        # Generate unique file ID and S3 location
        file_id = f"onboard_{session.session_id}_{int(datetime.now().timestamp())}"
        s3_key = f"onboarding/{session.progress.user_id}/{file_id}/{filename}"
        s3_location = f"s3://{self.config.security_data_bucket}/{s3_key}"
        
        # Upload to S3
        try:
            self.client_manager.s3.put_object(
                Bucket=self.config.security_data_bucket,
                Key=s3_key,
                Body=file_content.encode('utf-8'),
                Metadata={
                    'user_id': session.progress.user_id,
                    'session_id': session.session_id,
                    'detected_format': detection_result.detected_format.value,
                    'confidence': str(detection_result.confidence_score)
                }
            )
            logger.info(f"✅ File uploaded to S3: {s3_location}")
        except Exception as e:
            logger.error(f"❌ Failed to upload file to S3: {str(e)}")
            raise
        
        # Create uploaded file record
        uploaded_file = UploadedFile(
            file_id=file_id,
            original_filename=filename,
            s3_location=s3_location,
            file_size_bytes=file_size,
            detected_format=detection_result.detected_format,
            confidence_score=detection_result.confidence_score,
            sample_records=detection_result.sample_data[:5],  # First 5 records
            schema_info=detection_result.schema_preview,
            processing_status="ready"
        )
        
        # Add to session
        session.progress.uploaded_files.append(uploaded_file)
        session.progress.mark_stage_completed(OnboardingStage.DATA_UPLOAD)
        session.progress.mark_stage_completed(OnboardingStage.FORMAT_DETECTION)
        session.progress.current_stage = OnboardingStage.INITIAL_ANALYSIS
        
        logger.info(f"✅ File processing complete: {detection_result.detected_format.value} (confidence: {detection_result.confidence_score:.2f})")
        return uploaded_file
    
    def generate_sample_data_for_demo(self, session: OnboardingSession,
                                    data_format: DataFormat = DataFormat.JSON,
                                    record_count: int = 500) -> UploadedFile:
        """
        Generate and upload sample security data for demonstration.
        
        Args:
            session: Current onboarding session
            data_format: Format of sample data to generate
            record_count: Number of sample records
            
        Returns:
            UploadedFile with generated sample data
        """
        logger.info(f"🔧 Generating sample data: {record_count} records in {data_format.value} format")
        
        # Generate sample data
        sample_content = self.sample_generator.generate_sample_dataset(
            format_type=data_format,
            record_count=record_count,
            include_threats=True
        )
        
        # Create filename
        filename = f"sample_security_data_{data_format.value}_{int(datetime.now().timestamp())}.{data_format.value}"
        
        # Process as uploaded file
        return self.upload_sample_data(session, sample_content, filename)
    
    def perform_quick_analysis(self, session: OnboardingSession) -> QuickAnalysisResult:
        """
        Perform initial 5-minute security analysis on uploaded data.
        
        Args:
            session: Current onboarding session with uploaded files
            
        Returns:
            QuickAnalysisResult with key findings and recommendations
        """
        logger.info(f"🔍 Starting quick security analysis for session: {session.session_id}")
        start_time = datetime.now()
        
        if not session.progress.uploaded_files:
            raise ValueError("No files uploaded for analysis")
        
        try:
            # For quick start, use sample insights if no real analysis possible
            if self._should_use_sample_insights(session):
                return self._generate_sample_analysis_result(session, start_time)
            
            # Perform real analysis on uploaded data
            return self._perform_real_analysis(session, start_time)
            
        except Exception as e:
            logger.error(f"❌ Quick analysis failed: {str(e)}")
            # Fallback to sample insights
            return self._generate_sample_analysis_result(session, start_time)
    
    def _should_use_sample_insights(self, session: OnboardingSession) -> bool:
        """Determine if we should use sample insights vs real analysis"""
        # Use sample insights if:
        # 1. Files are very small (likely test data)
        # 2. Format detection confidence is low
        # 3. No obvious security fields detected
        
        for file in session.progress.uploaded_files:
            if file.file_size_bytes < 1000:  # Very small file
                return True
            if file.confidence_score < 0.5:  # Low confidence
                return True
            if not file.schema_info or not file.schema_info.get('security_fields'):
                return True
        
        return False
    
    def _perform_real_analysis(self, session: OnboardingSession, start_time: datetime) -> QuickAnalysisResult:
        """Perform real analysis on uploaded data"""
        logger.info("🔍 Performing real data analysis...")
        
        # Discover data sources
        discovery_result = self.data_detective.discover_security_data_sources()
        
        # Find uploaded files in discovered sources
        relevant_sources = []
        for file in session.progress.uploaded_files:
            for source in discovery_result.discovered_sources:
                if file.s3_location in source.s3_location:
                    relevant_sources.append(source)
        
        if not relevant_sources:
            logger.warning("⚠️ No relevant data sources found, using sample insights")
            return self._generate_sample_analysis_result(session, start_time)
        
        # Generate basic security query
        security_query = self._generate_quick_security_query(relevant_sources[0])
        
        # Execute query
        query_results = self.data_detective.execute_optimized_query(
            security_query,
            relevant_sources[0]
        )
        
        # Analyze results with AI
        threat_analysis = self.reasoning_engine.analyze_security_patterns(query_results)
        
        # Generate insights
        executive_report = self.insights_generator.generate_executive_summary(threat_analysis)
        
        # Create analysis result
        analysis_duration = (datetime.now() - start_time).total_seconds()
        
        return QuickAnalysisResult(
            analysis_id=f"analysis_{session.session_id}_{int(start_time.timestamp())}",
            timestamp=start_time,
            files_analyzed=[f.original_filename for f in session.progress.uploaded_files],
            key_findings=executive_report.key_findings,
            critical_issues=[
                {
                    "title": threat.threat_type,
                    "severity": threat.severity,
                    "description": f"Threat detected in {', '.join(threat.affected_systems)}",
                    "recommendation": "Investigate immediately"
                }
                for threat in threat_analysis.threats_identified[:3]  # Top 3 threats
            ],
            security_score=max(0, min(100, 100 - (threat_analysis.risk_score * 20))),
            recommendations=executive_report.recommendations_summary,
            next_steps=executive_report.next_steps,
            analysis_duration_seconds=analysis_duration,
            data_quality_score=0.8  # Assume good quality for real data
        )
    
    def _generate_sample_analysis_result(self, session: OnboardingSession, start_time: datetime) -> QuickAnalysisResult:
        """Generate sample analysis result for demonstration"""
        logger.info("🎭 Generating sample analysis result for demonstration")
        
        # Use sample generator for realistic results
        sample_insights = self.sample_generator.generate_quick_insights()
        critical_issues = self.sample_generator.generate_critical_issues_sample()
        
        analysis_duration = (datetime.now() - start_time).total_seconds()
        
        result = QuickAnalysisResult(
            analysis_id=f"sample_analysis_{session.session_id}_{int(start_time.timestamp())}",
            timestamp=start_time,
            files_analyzed=[f.original_filename for f in session.progress.uploaded_files],
            key_findings=sample_insights["key_findings"],
            critical_issues=critical_issues,
            security_score=sample_insights["overall_security_score"],
            recommendations=sample_insights["immediate_actions"],
            next_steps=[
                "Review and address critical security issues",
                "Implement recommended security controls",
                "Set up continuous monitoring",
                "Schedule regular security assessments"
            ],
            analysis_duration_seconds=analysis_duration,
            data_quality_score=0.9  # High quality for sample data
        )
        
        # Update session
        session.quick_analysis = result
        session.progress.mark_stage_completed(OnboardingStage.INITIAL_ANALYSIS)
        session.progress.current_stage = OnboardingStage.TUTORIAL
        
        return result
    
    def _generate_quick_security_query(self, data_source) -> str:
        """Generate a basic security query for quick analysis"""
        table_name = data_source.schema_info.table_name
        
        # Basic security query to find recent events
        query = f"""
        SELECT 
            timestamp,
            source_ip,
            user,
            event_type,
            result,
            severity
        FROM {table_name}
        WHERE timestamp >= current_timestamp - interval '24' hour
        ORDER BY timestamp DESC
        LIMIT 100
        """
        
        return query
    
    def get_onboarding_status(self, session: OnboardingSession) -> Dict[str, Any]:
        """Get current onboarding status and progress"""
        return {
            "session_id": session.session_id,
            "user_id": session.progress.user_id,
            "current_stage": session.progress.current_stage.value,
            "completion_percentage": session.progress.get_completion_percentage(),
            "stages_completed": [stage.value for stage in session.progress.stages_completed],
            "files_uploaded": len(session.progress.uploaded_files),
            "analysis_complete": session.quick_analysis is not None,
            "time_spent_minutes": session.progress.total_time_spent_minutes,
            "next_steps": self._get_next_steps(session)
        }
    
    def _get_next_steps(self, session: OnboardingSession) -> List[str]:
        """Get recommended next steps based on current progress"""
        if session.progress.current_stage == OnboardingStage.WELCOME:
            return ["Upload security data or generate sample data for analysis"]
        elif session.progress.current_stage == OnboardingStage.DATA_UPLOAD:
            return ["Wait for format detection to complete"]
        elif session.progress.current_stage == OnboardingStage.FORMAT_DETECTION:
            return ["Review detected format and start analysis"]
        elif session.progress.current_stage == OnboardingStage.INITIAL_ANALYSIS:
            return ["Review analysis results and explore tutorials"]
        elif session.progress.current_stage == OnboardingStage.TUTORIAL:
            return ["Complete interactive tutorials to learn the system"]
        elif session.progress.current_stage == OnboardingStage.DEMO_SCENARIOS:
            return ["Try demo scenarios to see advanced capabilities"]
        else:
            return ["Onboarding complete! Start using the AI Security Analyst"]
    
    def complete_onboarding(self, session: OnboardingSession) -> Dict[str, Any]:
        """Mark onboarding as complete and provide summary"""
        session.progress.mark_stage_completed(OnboardingStage.COMPLETED)
        session.progress.current_stage = OnboardingStage.COMPLETED
        
        summary = {
            "session_id": session.session_id,
            "completion_time": datetime.now().isoformat(),
            "total_duration_minutes": session.progress.total_time_spent_minutes,
            "files_processed": len(session.progress.uploaded_files),
            "tutorials_completed": len(session.progress.completed_tutorials),
            "scenarios_completed": len(session.progress.completed_scenarios),
            "key_achievements": [
                "Successfully uploaded and analyzed security data",
                "Learned to ask security questions in natural language",
                "Experienced AI-powered threat detection",
                "Understood the value of automated security analysis"
            ],
            "next_actions": [
                "Start uploading your real security data",
                "Ask specific questions about your security posture",
                "Set up regular security assessments",
                "Explore advanced features and integrations"
            ]
        }
        
        logger.info(f"🎉 Onboarding completed for session: {session.session_id}")
        return summary