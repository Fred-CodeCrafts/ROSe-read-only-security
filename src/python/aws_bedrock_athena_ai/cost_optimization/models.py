"""
Data models for cost optimization and monitoring
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum


class ServiceType(Enum):
    """AWS service types for cost tracking"""
    ATHENA = "athena"
    BEDROCK = "bedrock"
    S3 = "s3"
    CLOUDWATCH = "cloudwatch"


class ThrottleLevel(Enum):
    """Throttling levels based on usage"""
    NONE = "none"
    LIGHT = "light"
    MODERATE = "moderate"
    HEAVY = "heavy"
    BLOCKED = "blocked"


@dataclass
class FreeTierLimits:
    """AWS Free Tier limits for different services"""
    
    # Athena Free Tier: 10 TB of data scanned per month
    athena_data_scanned_gb_monthly: float = 10240.0  # 10 TB in GB
    
    # Bedrock Free Tier varies by model - using Claude 3 Haiku limits
    bedrock_input_tokens_monthly: int = 25000
    bedrock_output_tokens_monthly: int = 25000
    
    # S3 Free Tier: 5 GB storage, 20,000 GET requests, 2,000 PUT requests
    s3_storage_gb_monthly: float = 5.0
    s3_get_requests_monthly: int = 20000
    s3_put_requests_monthly: int = 2000
    
    # CloudWatch Free Tier: 10 custom metrics, 1 million API requests
    cloudwatch_custom_metrics_monthly: int = 10
    cloudwatch_api_requests_monthly: int = 1000000


@dataclass
class UsageMetrics:
    """Current usage metrics for a service"""
    service_type: ServiceType
    period_start: datetime
    period_end: datetime
    
    # Athena metrics
    data_scanned_gb: float = 0.0
    queries_executed: int = 0
    
    # Bedrock metrics  
    input_tokens_used: int = 0
    output_tokens_used: int = 0
    model_invocations: int = 0
    
    # S3 metrics
    storage_used_gb: float = 0.0
    get_requests: int = 0
    put_requests: int = 0
    
    # CloudWatch metrics
    custom_metrics_used: int = 0
    api_requests: int = 0
    
    # Cost estimates
    estimated_cost_usd: float = 0.0
    
    def get_usage_percentage(self, limits: FreeTierLimits) -> float:
        """Calculate usage percentage against Free Tier limits"""
        if self.service_type == ServiceType.ATHENA:
            return (self.data_scanned_gb / limits.athena_data_scanned_gb_monthly) * 100
        elif self.service_type == ServiceType.BEDROCK:
            input_pct = (self.input_tokens_used / limits.bedrock_input_tokens_monthly) * 100
            output_pct = (self.output_tokens_used / limits.bedrock_output_tokens_monthly) * 100
            return max(input_pct, output_pct)
        elif self.service_type == ServiceType.S3:
            storage_pct = (self.storage_used_gb / limits.s3_storage_gb_monthly) * 100
            get_pct = (self.get_requests / limits.s3_get_requests_monthly) * 100
            put_pct = (self.put_requests / limits.s3_put_requests_monthly) * 100
            return max(storage_pct, get_pct, put_pct)
        elif self.service_type == ServiceType.CLOUDWATCH:
            metrics_pct = (self.custom_metrics_used / limits.cloudwatch_custom_metrics_monthly) * 100
            api_pct = (self.api_requests / limits.cloudwatch_api_requests_monthly) * 100
            return max(metrics_pct, api_pct)
        return 0.0


@dataclass
class ThrottlingConfig:
    """Configuration for intelligent throttling"""
    
    # Usage thresholds for different throttle levels
    light_throttle_threshold: float = 60.0  # 60% of Free Tier
    moderate_throttle_threshold: float = 75.0  # 75% of Free Tier
    heavy_throttle_threshold: float = 85.0  # 85% of Free Tier
    block_threshold: float = 95.0  # 95% of Free Tier
    
    # Throttling actions
    light_throttle_delay_seconds: float = 1.0
    moderate_throttle_delay_seconds: float = 3.0
    heavy_throttle_delay_seconds: float = 10.0
    
    # Priority queue settings
    high_priority_bypass: bool = True
    critical_query_bypass: bool = True


@dataclass
class CacheEntry:
    """Cache entry for query results and insights"""
    key: str
    value: Any
    created_at: datetime
    last_accessed: datetime
    access_count: int = 0
    ttl_seconds: int = 3600  # 1 hour default
    size_bytes: int = 0
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        return datetime.utcnow() > (self.created_at + timedelta(seconds=self.ttl_seconds))
    
    def update_access(self):
        """Update access statistics"""
        self.last_accessed = datetime.utcnow()
        self.access_count += 1


@dataclass
class CacheStats:
    """Cache performance statistics"""
    total_entries: int = 0
    total_size_bytes: int = 0
    hit_count: int = 0
    miss_count: int = 0
    eviction_count: int = 0
    
    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate"""
        total_requests = self.hit_count + self.miss_count
        return (self.hit_count / total_requests * 100) if total_requests > 0 else 0.0
    
    @property
    def size_mb(self) -> float:
        """Get cache size in MB"""
        return self.total_size_bytes / (1024 * 1024)


@dataclass
class ModelSelectionCriteria:
    """Criteria for selecting optimal Bedrock model"""
    query_complexity: str  # "simple", "moderate", "complex"
    response_length_required: str  # "short", "medium", "long"
    accuracy_priority: str  # "speed", "balanced", "accuracy"
    available_budget_tokens: int
    
    def get_recommended_model(self) -> str:
        """Get recommended model based on criteria"""
        # Simple heuristic for model selection
        if self.accuracy_priority == "speed" and self.query_complexity == "simple":
            return "anthropic.claude-3-haiku-20240307-v1:0"  # Fastest, cheapest
        elif self.query_complexity == "complex" or self.accuracy_priority == "accuracy":
            return "anthropic.claude-3-sonnet-20240229-v1:0"  # More capable
        else:
            return "anthropic.claude-3-haiku-20240307-v1:0"  # Default to cost-effective


@dataclass
class OptimizationRecommendation:
    """Recommendation for cost optimization"""
    service_type: ServiceType
    recommendation_type: str
    description: str
    potential_savings_usd: float
    implementation_effort: str  # "low", "medium", "high"
    priority: str  # "low", "medium", "high", "critical"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'service_type': self.service_type.value,
            'recommendation_type': self.recommendation_type,
            'description': self.description,
            'potential_savings_usd': self.potential_savings_usd,
            'implementation_effort': self.implementation_effort,
            'priority': self.priority
        }