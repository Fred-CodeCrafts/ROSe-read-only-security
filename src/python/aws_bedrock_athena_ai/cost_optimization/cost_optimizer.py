"""
Cost Optimizer Integration

Integrates usage tracking, throttling, caching, and model selection
to provide comprehensive cost optimization for the AI Security Analyst.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable

from aws_bedrock_athena_ai.cost_optimization.usage_tracker import UsageTracker
from aws_bedrock_athena_ai.cost_optimization.throttling_manager import ThrottlingManager, RequestPriority
from aws_bedrock_athena_ai.cost_optimization.cache_manager import CacheManager
from aws_bedrock_athena_ai.cost_optimization.model_selector import ModelSelector, ModelSelectionCriteria
from aws_bedrock_athena_ai.cost_optimization.models import ServiceType, FreeTierLimits, OptimizationRecommendation

logger = logging.getLogger(__name__)


class CostOptimizer:
    """Main cost optimization coordinator"""
    
    def __init__(self, aws_clients, 
                 limits: Optional[FreeTierLimits] = None,
                 cache_size_mb: int = 100):
        
        # Initialize components
        self.usage_tracker = UsageTracker(aws_clients, limits)
        self.throttling_manager = ThrottlingManager(self.usage_tracker)
        self.cache_manager = CacheManager(max_size_mb=cache_size_mb)
        self.model_selector = ModelSelector()
        
        # Configuration
        self.aws_clients = aws_clients
        self.limits = limits or FreeTierLimits()
        
        # Statistics
        self.optimization_stats = {
            'queries_cached': 0,
            'queries_throttled': 0,
            'cost_saved_usd': 0.0,
            'model_optimizations': 0
        }
    
    async def execute_athena_query(self, 
                                  query: str,
                                  parameters: Dict[str, Any],
                                  priority: RequestPriority = RequestPriority.NORMAL,
                                  use_cache: bool = True) -> Any:
        """Execute Athena query with full optimization"""
        
        # Try cache first
        if use_cache:
            cached_result = self.cache_manager.get_cached_query_result(query, parameters)
            if cached_result is not None:
                self.optimization_stats['queries_cached'] += 1
                logger.info("Using cached Athena query result")
                return cached_result
        
        # Execute with throttling
        async def execute_query():
            # This would integrate with the actual Athena query execution
            # For now, it's a placeholder
            logger.info(f"Executing Athena query with parameters: {parameters}")
            # result = await actual_athena_execution(query, parameters)
            result = {"placeholder": "query_result"}
            return result
        
        result = await self.throttling_manager.execute_with_throttling(
            ServiceType.ATHENA,
            execute_query,
            priority
        )
        
        # Cache the result
        if use_cache and result:
            self.cache_manager.cache_query_result(query, parameters, result)
        
        return result
    
    async def execute_bedrock_inference(self,
                                      prompt: str,
                                      query_complexity: str = "moderate",
                                      accuracy_priority: str = "balanced",
                                      priority: RequestPriority = RequestPriority.NORMAL,
                                      use_cache: bool = True) -> Any:
        """Execute Bedrock inference with optimization"""
        
        # Select optimal model
        criteria = ModelSelectionCriteria(
            query_complexity=query_complexity,
            response_length_required="medium",
            accuracy_priority=accuracy_priority,
            available_budget_tokens=5000  # Adjust based on remaining budget
        )
        
        model_id = self.model_selector.select_model(criteria)
        self.optimization_stats['model_optimizations'] += 1
        
        # Try cache first
        if use_cache:
            cached_result = self.cache_manager.get_cached_ai_insight(prompt, model_id)
            if cached_result is not None:
                self.optimization_stats['queries_cached'] += 1
                logger.info("Using cached Bedrock inference result")
                return cached_result
        
        # Execute with throttling
        async def execute_inference():
            # This would integrate with the actual Bedrock inference
            logger.info(f"Executing Bedrock inference with model: {model_id}")
            # result = await actual_bedrock_inference(model_id, prompt)
            result = {"model_id": model_id, "response": "placeholder_response"}
            return result
        
        result = await self.throttling_manager.execute_with_throttling(
            ServiceType.BEDROCK,
            execute_inference,
            priority
        )
        
        # Cache the result
        if use_cache and result:
            self.cache_manager.cache_ai_insight(prompt, model_id, result)
        
        return result
    
    def get_optimization_dashboard(self) -> Dict[str, Any]:
        """Get comprehensive optimization status dashboard"""
        
        # Get usage summary
        usage_summary = self.usage_tracker.get_all_usage_summary()
        
        # Get throttling status
        throttling_status = self.throttling_manager.get_throttling_status()
        
        # Get cache stats
        cache_info = self.cache_manager.get_cache_info()
        
        # Get recommendations
        recommendations = self.usage_tracker.get_optimization_recommendations()
        
        # Calculate savings
        total_estimated_cost = sum(
            usage.estimated_cost_usd for usage in usage_summary.values()
        )
        
        dashboard = {
            'timestamp': datetime.utcnow().isoformat(),
            'usage_summary': {
                service: {
                    'usage_percentage': usage.get_usage_percentage(self.limits),
                    'estimated_cost_usd': usage.estimated_cost_usd,
                    'service_specific_metrics': self._get_service_metrics(service, usage)
                }
                for service, usage in usage_summary.items()
            },
            'throttling_status': throttling_status,
            'cache_performance': cache_info,
            'optimization_stats': self.optimization_stats,
            'cost_analysis': {
                'total_estimated_cost_usd': total_estimated_cost,
                'estimated_savings_usd': self.optimization_stats['cost_saved_usd'],
                'free_tier_status': self._get_free_tier_status(usage_summary)
            },
            'recommendations': [rec.to_dict() for rec in recommendations],
            'model_recommendations': self.model_selector.get_free_tier_recommendations()
        }
        
        return dashboard
    
    def _get_service_metrics(self, service_name: str, usage) -> Dict[str, Any]:
        """Get service-specific metrics"""
        
        service_type = ServiceType(service_name)
        
        if service_type == ServiceType.ATHENA:
            return {
                'data_scanned_gb': usage.data_scanned_gb,
                'queries_executed': usage.queries_executed
            }
        elif service_type == ServiceType.BEDROCK:
            return {
                'input_tokens_used': usage.input_tokens_used,
                'output_tokens_used': usage.output_tokens_used,
                'model_invocations': usage.model_invocations
            }
        elif service_type == ServiceType.S3:
            return {
                'storage_used_gb': usage.storage_used_gb,
                'get_requests': usage.get_requests,
                'put_requests': usage.put_requests
            }
        else:
            return {}
    
    def _get_free_tier_status(self, usage_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Get Free Tier status summary"""
        
        status = {
            'overall_status': 'healthy',
            'services_at_risk': [],
            'days_remaining_estimate': 30
        }
        
        for service_name, usage in usage_summary.items():
            usage_pct = usage.get_usage_percentage(self.limits)
            
            if usage_pct > 90:
                status['overall_status'] = 'critical'
                status['services_at_risk'].append(service_name)
            elif usage_pct > 75:
                if status['overall_status'] == 'healthy':
                    status['overall_status'] = 'warning'
                status['services_at_risk'].append(service_name)
        
        return status
    
    def optimize_performance(self):
        """Run performance optimization tasks"""
        
        logger.info("Running performance optimization...")
        
        # Clean up expired cache entries
        expired_count = self.cache_manager.cleanup_expired()
        
        # Optimize cache
        self.cache_manager.optimize_cache()
        
        # Process queued requests
        self.throttling_manager.process_queued_requests()
        
        # Force usage check
        self.throttling_manager.force_usage_check()
        
        # Publish metrics
        self.usage_tracker.publish_usage_metrics()
        
        logger.info(f"Performance optimization complete. Cleaned {expired_count} expired cache entries.")
    
    def get_cost_projections(self, days_ahead: int = 30) -> Dict[str, Any]:
        """Project costs for the next period"""
        
        usage_summary = self.usage_tracker.get_all_usage_summary()
        
        projections = {}
        
        for service_name, usage in usage_summary.items():
            # Calculate daily usage rate
            period_days = (usage.period_end - usage.period_start).days
            if period_days > 0:
                daily_cost = usage.estimated_cost_usd / period_days
                projected_cost = daily_cost * days_ahead
                
                projections[service_name] = {
                    'current_daily_cost': daily_cost,
                    'projected_cost': projected_cost,
                    'free_tier_risk': projected_cost > 0  # Any cost means we're exceeding Free Tier
                }
        
        return {
            'projection_period_days': days_ahead,
            'service_projections': projections,
            'total_projected_cost': sum(p['projected_cost'] for p in projections.values()),
            'recommendations': self._get_cost_reduction_recommendations(projections)
        }
    
    def _get_cost_reduction_recommendations(self, projections: Dict[str, Any]) -> List[str]:
        """Get recommendations to reduce projected costs"""
        
        recommendations = []
        
        for service, projection in projections.items():
            if projection['projected_cost'] > 1.0:  # More than $1 projected
                if service == 'athena':
                    recommendations.append(
                        "Consider optimizing Athena queries with better partitioning and columnar formats"
                    )
                elif service == 'bedrock':
                    recommendations.append(
                        "Use Claude 3 Haiku for simpler queries to reduce Bedrock costs"
                    )
        
        if not recommendations:
            recommendations.append("Current usage is within Free Tier projections")
        
        return recommendations
    
    async def emergency_cost_control(self):
        """Activate emergency cost control measures"""
        
        logger.warning("Activating emergency cost control measures")
        
        # Enable emergency throttling
        self.throttling_manager.set_emergency_mode(True)
        
        # Clear non-essential cache to free up resources
        cache_stats = self.cache_manager.get_cache_stats()
        if cache_stats.size_mb > 50:  # If cache is large, reduce it
            # Keep only the most accessed entries
            self.cache_manager.optimize_cache()
        
        # Get immediate recommendations
        recommendations = self.usage_tracker.get_optimization_recommendations()
        
        logger.warning(f"Emergency mode activated. {len(recommendations)} optimization recommendations available.")
        
        return {
            'emergency_mode': True,
            'actions_taken': [
                'Enabled heavy throttling for all services',
                'Optimized cache to reduce resource usage'
            ],
            'recommendations': [rec.to_dict() for rec in recommendations]
        }