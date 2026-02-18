"""
Data models for the onboarding and demonstration system.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class OnboardingStage(Enum):
    """Stages of the onboarding process"""
    WELCOME = "welcome"
    DATA_UPLOAD = "data_upload"
    FORMAT_DETECTION = "format_detection"
    INITIAL_ANALYSIS = "initial_analysis"
    TUTORIAL = "tutorial"
    DEMO_SCENARIOS = "demo_scenarios"
    COMPLETED = "completed"


class DataFormat(Enum):
    """Supported data formats for upload"""
    JSON = "json"
    CSV = "csv"
    PARQUET = "parquet"
    LOG_TEXT = "log_text"
    SYSLOG = "syslog"
    CLOUDTRAIL = "cloudtrail"
    VPC_FLOW = "vpc_flow"
    UNKNOWN = "unknown"


class TutorialType(Enum):
    """Types of interactive tutorials"""
    BASIC_QUESTIONS = "basic_questions"
    THREAT_HUNTING = "threat_hunting"
    COMPLIANCE_CHECK = "compliance_check"
    RISK_ASSESSMENT = "risk_assessment"
    INCIDENT_RESPONSE = "incident_response"


@dataclass
class UploadedFile:
    """Information about an uploaded data file"""
    file_id: str
    original_filename: str
    s3_location: str
    file_size_bytes: int
    detected_format: DataFormat
    confidence_score: float
    upload_timestamp: datetime = field(default_factory=datetime.now)
    sample_records: List[Dict[str, Any]] = field(default_factory=list)
    schema_info: Optional[Dict[str, Any]] = None
    processing_status: str = "uploaded"  # uploaded, processing, ready, error


@dataclass
class FormatDetectionResult:
    """Result of automatic format detection"""
    detected_format: DataFormat
    confidence_score: float
    schema_preview: Dict[str, Any]
    sample_data: List[Dict[str, Any]]
    recommendations: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class QuickAnalysisResult:
    """Result of initial 5-minute security analysis"""
    analysis_id: str
    timestamp: datetime
    files_analyzed: List[str]
    key_findings: List[str]
    critical_issues: List[Dict[str, Any]]
    security_score: float
    recommendations: List[str]
    next_steps: List[str]
    analysis_duration_seconds: float
    data_quality_score: float


@dataclass
class TutorialStep:
    """Individual step in a tutorial"""
    step_id: str
    title: str
    description: str
    example_question: str
    expected_outcome: str
    hints: List[str] = field(default_factory=list)
    completed: bool = False


@dataclass
class Tutorial:
    """Interactive tutorial for learning the system"""
    tutorial_id: str
    title: str
    description: str
    tutorial_type: TutorialType
    estimated_duration_minutes: int
    difficulty_level: str  # beginner, intermediate, advanced
    steps: List[TutorialStep] = field(default_factory=list)
    completion_percentage: float = 0.0
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class DemoScenario:
    """Pre-built demonstration scenario"""
    scenario_id: str
    title: str
    description: str
    scenario_type: str  # breach_detection, compliance_audit, risk_assessment
    sample_data_included: bool
    key_questions: List[str]
    expected_insights: List[str]
    business_value: str
    estimated_duration_minutes: int


@dataclass
class OnboardingProgress:
    """Tracks user progress through onboarding"""
    user_id: str
    current_stage: OnboardingStage
    stages_completed: List[OnboardingStage] = field(default_factory=list)
    uploaded_files: List[UploadedFile] = field(default_factory=list)
    completed_tutorials: List[str] = field(default_factory=list)
    completed_scenarios: List[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    total_time_spent_minutes: float = 0.0
    
    def is_stage_completed(self, stage: OnboardingStage) -> bool:
        """Check if a specific stage has been completed"""
        return stage in self.stages_completed
    
    def mark_stage_completed(self, stage: OnboardingStage):
        """Mark a stage as completed"""
        if stage not in self.stages_completed:
            self.stages_completed.append(stage)
        self.last_activity = datetime.now()
    
    def get_completion_percentage(self) -> float:
        """Calculate overall onboarding completion percentage"""
        total_stages = len(OnboardingStage)
        completed_stages = len(self.stages_completed)
        return (completed_stages / total_stages) * 100.0


@dataclass
class OnboardingSession:
    """Complete onboarding session data"""
    session_id: str
    progress: OnboardingProgress
    quick_analysis: Optional[QuickAnalysisResult] = None
    active_tutorial: Optional[Tutorial] = None
    available_scenarios: List[DemoScenario] = field(default_factory=list)
    session_notes: List[str] = field(default_factory=list)
    feedback: Optional[Dict[str, Any]] = None