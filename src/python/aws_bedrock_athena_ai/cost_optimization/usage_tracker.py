"""
Free Tier Usage Tracking for AWS Services

Monitors Athena query costs, Bedrock token usage, and other AWS service consumption
to stay within Free Tier limits and provide cost optimization recommendations.
"""

import boto3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import asdict

from aws_bedrock_athena_ai.cost_optimization.models import (
    ServiceType, UsageMetrics, FreeTierLimits, 
    OptimizationRecommendation, ThrottleLevel
)

logger = logging.getLogger(__name__)


class UsageTracker:
    """Tracks AWS service usage against Free Tier limits"""
    
    def __init__(self, aws_clients, limits: Optional[FreeTierLimits] = None):
        self.aws_clients = aws_clients
        self.limits = limits or FreeTierLimits()
        self.usage_history: List[UsageMetrics] = []
        
        # CloudWatch client for metrics
        self.cloudwatch = aws_clients.cloudwatch
        
    def get_current_usage(self, service_type: ServiceType, 
                         period_days: int = 30) -> UsageMetrics:
        """Get current usage metrics for a service"""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=period_days)
        
        if service_type == ServiceType.ATHENA:
            return self._get_athena_usage(start_time, end_time)
        elif service_type == ServiceType.BEDROCK:
            return self._get_bedrock_usage(start_time, end_time)
        elif service_type == ServiceType.S3:
            return self._get_s3_usage(start_time, end_time)
        elif service_type == ServiceType.CLOUDWATCH:
            return self._get_cloudwatch_usage(start_time, end_time)
        else:
            raise ValueError(f"Unsupported service type: {service_type}")
    
    def _get_athena_usage(self, start_time: datetime, end_time: datetime) -> UsageMetrics:
        """Get Athena usage metrics"""
        metrics = UsageMetrics(
            service_type=ServiceType.ATHENA,
            period_start=start_time,
            period_end=end_time
        )
        
        try:
            # Get query execution history
            athena = self.aws_clients.athena
            
            # List recent query executions
            response = athena.list_query_executions(
                MaxResults=1000  # Get recent queries
            )
            
            total_data_scanned = 0.0
            query_count = 0
            
            for execution_id in response.get('QueryExecutionIds', []):
                try:
                    execution = athena.get_query_execution(QueryExecutionId=execution_id)
                    execution_details = execution['QueryExecution']
                    
                    # Check if query is within our time range
                    completion_time = execution_details.get('Status', {}).get('CompletionDateTime')
                    if completion_time and start_time <= completion_time <= end_time:
                        # Get data scanned
                        statistics = execution_details.get('Statistics', {})
                        data_scanned_bytes = statistics.get('DataScannedInBytes', 0)
                        total_data_scanned += data_scanned_bytes / (1024**3)  # Convert to GB
                        query_count += 1
                        
                except Exception as e:
                    logger.warning(f"Failed to get query execution details: {e}")
                    continue
            
            metrics.data_scanned_gb = total_data_scanned
            metrics.queries_executed = query_count
            
            # Estimate cost (Athena charges $5 per TB scanned)
            metrics.estimated_cost_usd = (total_data_scanned / 1024) * 5.0
            
            logger.info(f"Athena usage: {total_data_scanned:.2f} GB scanned, {query_count} queries")
            
        except Exception as e:
            logger.error(f"Failed to get Athena usage metrics: {e}")
        
        return metrics
    
    def _get_bedrock_usage(self, start_time: datetime, end_time: datetime) -> UsageMetrics:
        """Get Bedrock usage metrics from CloudWatch"""
        metrics = UsageMetrics(
            service_type=ServiceType.BEDROCK,
            period_start=start_time,
            period_end=end_time
        )
        
        try:
            # Get CloudWatch metrics for Bedrock
            cloudwatch = self.cloudwatch
            
            # Get input token usage
            input_tokens_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/Bedrock',
                MetricName='InputTokenCount',
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,  # 1 hour periods
                Statistics=['Sum']
            )
            
            # Get output token usage
            output_tokens_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/Bedrock',
                MetricName='OutputTokenCount',
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Sum']
            )
            
            # Get invocation count
            invocations_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/Bedrock',
                MetricName='Invocations',
                StartTime=start_time,
                EndTime=end_time,
                Period=3600,
                Statistics=['Sum']
            )
            
            # Sum up the metrics
            metrics.input_tokens_used = sum(
                point['Sum'] for point in input_tokens_response.get('Datapoints', [])
            )
            metrics.output_tokens_used = sum(
                point['Sum'] for point in output_tokens_response.get('Datapoints', [])
            )
            metrics.model_invocations = sum(
                point['Sum'] for point in invocations_response.get('Datapoints', [])
            )
            
            # Estimate cost (rough estimate for Claude 3 Haiku)
            # Input: $0.25 per 1M tokens, Output: $1.25 per 1M tokens
            input_cost = (metrics.input_tokens_used / 1000000) * 0.25
            output_cost = (metrics.output_tokens_used / 1000000) * 1.25
            metrics.estimated_cost_usd = input_cost + output_cost
            
            logger.info(f"Bedrock usage: {metrics.input_tokens_used} input tokens, "
                       f"{metrics.output_tokens_used} output tokens, "
                       f"{metrics.model_invocations} invocations")
            
        except Exception as e:
            logger.error(f"Failed to get Bedrock usage metrics: {e}")
        
        return metrics
    
    def _get_s3_usage(self, start_time: datetime, end_time: datetime) -> UsageMetrics:
        """Get S3 usage metrics"""
        metrics = UsageMetrics(
            service_type=ServiceType.S3,
            period_start=start_time,
            period_end=end_time
        )
        
        try:
            cloudwatch = self.cloudwatch
            
            # Get storage metrics
            storage_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/S3',
                MetricName='BucketSizeBytes',
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,  # Daily
                Statistics=['Average'],
                Dimensions=[
                    {'Name': 'StorageType', 'Value': 'StandardStorage'}
                ]
            )
            
            # Get request metrics
            get_requests_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/S3',
                MetricName='NumberOfObjects',
                StartTime=start_time,
                EndTime=end_time,
                Period=86400,
                Statistics=['Sum']
            )
            
            if storage_response.get('Datapoints'):
                latest_storage = max(storage_response['Datapoints'], 
                                   key=lambda x: x['Timestamp'])
                metrics.storage_used_gb = latest_storage['Average'] / (1024**3)
            
            # Note: Detailed request metrics require CloudTrail or S3 access logging
            # For now, we'll use approximations
            
            logger.info(f"S3 usage: {metrics.storage_used_gb:.2f} GB storage")
            
        except Exception as e:
            logger.error(f"Failed to get S3 usage metrics: {e}")
        
        return metrics
    
    def _get_cloudwatch_usage(self, start_time: datetime, end_time: datetime) -> UsageMetrics:
        """Get CloudWatch usage metrics"""
        metrics = UsageMetrics(
            service_type=ServiceType.CLOUDWATCH,
            period_start=start_time,
            period_end=end_time
        )
        
        try:
            # CloudWatch usage is harder to track directly
            # We'll estimate based on our own metric publishing
            metrics.custom_metrics_used = 5  # Conservative estimate
            metrics.api_requests = 100  # Conservative estimate
            
            logger.info(f"CloudWatch usage: {metrics.custom_metrics_used} custom metrics")
            
        except Exception as e:
            logger.error(f"Failed to get CloudWatch usage metrics: {e}")
        
        return metrics
    
    def get_all_usage_summary(self) -> Dict[str, UsageMetrics]:
        """Get usage summary for all services"""
        summary = {}
        
        for service_type in ServiceType:
            try:
                usage = self.get_current_usage(service_type)
                summary[service_type.value] = usage
            except Exception as e:
                logger.error(f"Failed to get usage for {service_type.value}: {e}")
        
        return summary
    
    def get_throttle_level(self, service_type: ServiceType) -> ThrottleLevel:
        """Determine appropriate throttle level based on usage"""
        usage = self.get_current_usage(service_type)
        usage_percentage = usage.get_usage_percentage(self.limits)
        
        if usage_percentage >= 95.0:
            return ThrottleLevel.BLOCKED
        elif usage_percentage >= 85.0:
            return ThrottleLevel.HEAVY
        elif usage_percentage >= 75.0:
            return ThrottleLevel.MODERATE
        elif usage_percentage >= 60.0:
            return ThrottleLevel.LIGHT
        else:
            return ThrottleLevel.NONE
    
    def get_optimization_recommendations(self) -> List[OptimizationRecommendation]:
        """Generate cost optimization recommendations"""
        recommendations = []
        
        # Get current usage for all services
        usage_summary = self.get_all_usage_summary()
        
        for service_name, usage in usage_summary.items():
            service_type = ServiceType(service_name)
            usage_pct = usage.get_usage_percentage(self.limits)
            
            if usage_pct > 80.0:
                recommendations.append(OptimizationRecommendation(
                    service_type=service_type,
                    recommendation_type="usage_reduction",
                    description=f"High {service_name} usage ({usage_pct:.1f}%). "
                               f"Consider optimizing queries or caching results.",
                    potential_savings_usd=usage.estimated_cost_usd * 0.3,
                    implementation_effort="medium",
                    priority="high"
                ))
            
            # Service-specific recommendations
            if service_type == ServiceType.ATHENA and usage.data_scanned_gb > 1000:
                recommendations.append(OptimizationRecommendation(
                    service_type=service_type,
                    recommendation_type="query_optimization",
                    description="Large amount of data scanned. Use columnar formats "
                               "and partition pruning to reduce costs.",
                    potential_savings_usd=usage.estimated_cost_usd * 0.5,
                    implementation_effort="medium",
                    priority="high"
                ))
            
            if service_type == ServiceType.BEDROCK and usage.output_tokens_used > 20000:
                recommendations.append(OptimizationRecommendation(
                    service_type=service_type,
                    recommendation_type="model_optimization",
                    description="High token usage. Consider using more efficient models "
                               "or reducing response length.",
                    potential_savings_usd=usage.estimated_cost_usd * 0.4,
                    implementation_effort="low",
                    priority="medium"
                ))
        
        return recommendations
    
    def publish_usage_metrics(self):
        """Publish usage metrics to CloudWatch for monitoring"""
        try:
            usage_summary = self.get_all_usage_summary()
            
            for service_name, usage in usage_summary.items():
                usage_pct = usage.get_usage_percentage(self.limits)
                
                # Publish usage percentage metric
                self.cloudwatch.put_metric_data(
                    Namespace='AISecurityAnalyst/Usage',
                    MetricData=[
                        {
                            'MetricName': 'FreeTierUsagePercentage',
                            'Dimensions': [
                                {'Name': 'Service', 'Value': service_name}
                            ],
                            'Value': usage_pct,
                            'Unit': 'Percent',
                            'Timestamp': datetime.utcnow()
                        }
                    ]
                )
                
                # Publish cost estimate
                self.cloudwatch.put_metric_data(
                    Namespace='AISecurityAnalyst/Cost',
                    MetricData=[
                        {
                            'MetricName': 'EstimatedCostUSD',
                            'Dimensions': [
                                {'Name': 'Service', 'Value': service_name}
                            ],
                            'Value': usage.estimated_cost_usd,
                            'Unit': 'None',
                            'Timestamp': datetime.utcnow()
                        }
                    ]
                )
            
            logger.info("Successfully published usage metrics to CloudWatch")
            
        except Exception as e:
            logger.error(f"Failed to publish usage metrics: {e}")
    
    def save_usage_history(self, filepath: str):
        """Save usage history to file for analysis"""
        try:
            usage_summary = self.get_all_usage_summary()
            
            # Convert to serializable format
            history_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'usage_summary': {
                    service: asdict(usage) 
                    for service, usage in usage_summary.items()
                },
                'limits': asdict(self.limits),
                'recommendations': [
                    rec.to_dict() for rec in self.get_optimization_recommendations()
                ]
            }
            
            with open(filepath, 'w') as f:
                json.dump(history_data, f, indent=2, default=str)
            
            logger.info(f"Usage history saved to {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to save usage history: {e}")