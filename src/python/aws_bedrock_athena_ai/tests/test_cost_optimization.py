"""
Tests for cost optimization and monitoring components
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock

from aws_bedrock_athena_ai.cost_optimization import (
    UsageTracker, ThrottlingManager, CacheManager, ModelSelector, CostOptimizer
)
from aws_bedrock_athena_ai.cost_optimization.models import (
    ServiceType, FreeTierLimits, ModelSelectionCriteria, ThrottleLevel
)


class TestUsageTracker:
    """Test usage tracking functionality"""
    
    def test_usage_tracker_initialization(self):
        """Test that usage tracker initializes correctly"""
        mock_clients = Mock()
        mock_clients.cloudwatch = Mock()
        
        tracker = UsageTracker(mock_clients)
        
        assert tracker.aws_clients == mock_clients
        assert isinstance(tracker.limits, FreeTierLimits)
        assert tracker.usage_history == []
    
    def test_get_throttle_level(self):
        """Test throttle level determination"""
        mock_clients = Mock()
        mock_clients.cloudwatch = Mock()
        
        tracker = UsageTracker(mock_clients)
        
        # Mock usage that returns high percentage
        mock_usage = Mock()
        mock_usage.get_usage_percentage.return_value = 90.0
        
        tracker.get_current_usage = Mock(return_value=mock_usage)
        
        throttle_level = tracker.get_throttle_level(ServiceType.ATHENA)
        assert throttle_level == ThrottleLevel.HEAVY


class TestCacheManager:
    """Test caching functionality"""
    
    def test_cache_manager_initialization(self):
        """Test cache manager initialization"""
        cache = CacheManager(max_size_mb=50, default_ttl_seconds=1800)
        
        assert cache.max_size_bytes == 50 * 1024 * 1024
        assert cache.default_ttl_seconds == 1800
        assert len(cache.cache) == 0
    
    def test_cache_put_and_get(self):
        """Test basic cache operations"""
        cache = CacheManager(max_size_mb=10)
        
        # Put a value
        success = cache.put("test_key", {"data": "test_value"})
        assert success
        
        # Get the value
        result = cache.get("test_key")
        assert result == {"data": "test_value"}
        
        # Get non-existent key
        result = cache.get("non_existent")
        assert result is None
    
    def test_cache_query_result(self):
        """Test query result caching"""
        cache = CacheManager(max_size_mb=10)
        
        query = "SELECT * FROM security_events WHERE timestamp > ?"
        parameters = {"timestamp": "2024-01-01"}
        result = {"rows": [{"event": "login"}]}
        
        # Cache the result
        key = cache.cache_query_result(query, parameters, result)
        assert key != ""
        
        # Retrieve the result
        cached_result = cache.get_cached_query_result(query, parameters)
        assert cached_result == result
    
    def test_cache_ai_insight(self):
        """Test AI insight caching"""
        cache = CacheManager(max_size_mb=10)
        
        input_data = "Analyze security threats"
        model_id = "claude-3-haiku"
        insight = {"threats": ["suspicious_login"], "risk_level": "medium"}
        
        # Cache the insight
        key = cache.cache_ai_insight(input_data, model_id, insight)
        assert key != ""
        
        # Retrieve the insight
        cached_insight = cache.get_cached_ai_insight(input_data, model_id)
        assert cached_insight == insight


class TestModelSelector:
    """Test model selection functionality"""
    
    def test_model_selector_initialization(self):
        """Test model selector initialization"""
        selector = ModelSelector()
        
        assert len(selector.available_models) > 0
        assert selector.default_model_id in selector.available_models
    
    def test_select_model_simple_query(self):
        """Test model selection for simple queries"""
        selector = ModelSelector()
        
        criteria = ModelSelectionCriteria(
            query_complexity="simple",
            response_length_required="short",
            accuracy_priority="speed",
            available_budget_tokens=1000
        )
        
        model_id = selector.select_model(criteria)
        
        # Should select the fastest/cheapest model for simple queries
        assert model_id == "anthropic.claude-3-haiku-20240307-v1:0"
    
    def test_select_model_complex_query(self):
        """Test model selection for complex queries"""
        selector = ModelSelector()
        
        criteria = ModelSelectionCriteria(
            query_complexity="complex",
            response_length_required="long",
            accuracy_priority="accuracy",
            available_budget_tokens=10000
        )
        
        model_id = selector.select_model(criteria)
        
        # Should select a more capable model for complex queries
        assert model_id in selector.available_models
        model_info = selector.available_models[model_id]
        assert model_info.supports_complex_reasoning
    
    def test_estimate_monthly_cost(self):
        """Test monthly cost estimation"""
        selector = ModelSelector()
        
        model_id = "anthropic.claude-3-haiku-20240307-v1:0"
        cost_estimate = selector.estimate_monthly_cost(
            model_id=model_id,
            queries_per_day=10,
            avg_input_tokens=500,
            avg_output_tokens=300
        )
        
        assert "monthly_cost_usd" in cost_estimate
        assert cost_estimate["monthly_cost_usd"] >= 0
        assert cost_estimate["monthly_queries"] == 300  # 10 * 30
    
    def test_get_free_tier_recommendations(self):
        """Test Free Tier recommendations"""
        selector = ModelSelector()
        
        recommendations = selector.get_free_tier_recommendations()
        
        assert "primary_model" in recommendations
        assert "max_queries_per_month" in recommendations
        assert "optimization_tips" in recommendations
        assert len(recommendations["optimization_tips"]) > 0


class TestThrottlingManager:
    """Test throttling functionality"""
    
    def test_throttling_manager_initialization(self):
        """Test throttling manager initialization"""
        mock_tracker = Mock()
        manager = ThrottlingManager(mock_tracker)
        
        assert manager.usage_tracker == mock_tracker
        assert len(manager.request_queues) > 0
        assert manager.throttled_requests_count == 0
    
    def test_should_throttle_normal_usage(self):
        """Test throttling decision for normal usage"""
        mock_tracker = Mock()
        mock_tracker.get_throttle_level.return_value = ThrottleLevel.NONE
        
        manager = ThrottlingManager(mock_tracker)
        
        # Should not throttle when usage is normal
        should_throttle = manager.should_throttle(ServiceType.ATHENA)
        assert not should_throttle
    
    def test_should_throttle_high_usage(self):
        """Test throttling decision for high usage"""
        mock_tracker = Mock()
        mock_tracker.get_throttle_level.return_value = ThrottleLevel.HEAVY
        
        manager = ThrottlingManager(mock_tracker)
        
        # Should throttle when usage is high
        should_throttle = manager.should_throttle(ServiceType.ATHENA)
        assert should_throttle
    
    def test_get_throttle_delay(self):
        """Test throttle delay calculation"""
        mock_tracker = Mock()
        manager = ThrottlingManager(mock_tracker)
        
        # Set throttle level
        manager.current_throttle_levels[ServiceType.ATHENA] = ThrottleLevel.MODERATE
        
        delay = manager.get_throttle_delay(ServiceType.ATHENA)
        assert delay > 0
        assert delay == manager.config.moderate_throttle_delay_seconds


class TestCostOptimizer:
    """Test integrated cost optimizer"""
    
    def test_cost_optimizer_initialization(self):
        """Test cost optimizer initialization"""
        mock_clients = Mock()
        mock_clients.cloudwatch = Mock()
        
        optimizer = CostOptimizer(mock_clients)
        
        assert optimizer.aws_clients == mock_clients
        assert isinstance(optimizer.usage_tracker, UsageTracker)
        assert isinstance(optimizer.throttling_manager, ThrottlingManager)
        assert isinstance(optimizer.cache_manager, CacheManager)
        assert isinstance(optimizer.model_selector, ModelSelector)
    
    def test_get_optimization_dashboard(self):
        """Test optimization dashboard generation"""
        mock_clients = Mock()
        mock_clients.cloudwatch = Mock()
        
        optimizer = CostOptimizer(mock_clients)
        
        # Mock the usage tracker to return some data
        mock_usage = Mock()
        mock_usage.get_usage_percentage.return_value = 50.0
        mock_usage.estimated_cost_usd = 2.50
        
        optimizer.usage_tracker.get_all_usage_summary = Mock(return_value={
            'athena': mock_usage
        })
        optimizer.usage_tracker.get_optimization_recommendations = Mock(return_value=[])
        
        dashboard = optimizer.get_optimization_dashboard()
        
        assert "timestamp" in dashboard
        assert "usage_summary" in dashboard
        assert "throttling_status" in dashboard
        assert "cache_performance" in dashboard
        assert "cost_analysis" in dashboard
        assert "recommendations" in dashboard
    
    def test_get_cost_projections(self):
        """Test cost projections"""
        mock_clients = Mock()
        mock_clients.cloudwatch = Mock()
        
        optimizer = CostOptimizer(mock_clients)
        
        # Mock usage data
        mock_usage = Mock()
        mock_usage.period_start = datetime.utcnow() - timedelta(days=7)
        mock_usage.period_end = datetime.utcnow()
        mock_usage.estimated_cost_usd = 1.40  # $0.20 per day
        
        optimizer.usage_tracker.get_all_usage_summary = Mock(return_value={
            'athena': mock_usage
        })
        
        projections = optimizer.get_cost_projections(days_ahead=30)
        
        assert "projection_period_days" in projections
        assert projections["projection_period_days"] == 30
        assert "service_projections" in projections
        assert "total_projected_cost" in projections


if __name__ == "__main__":
    pytest.main([__file__])