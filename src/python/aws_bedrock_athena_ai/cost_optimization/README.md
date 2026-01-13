# Cost Optimization and Monitoring

This module provides comprehensive cost optimization and monitoring capabilities for the AI Security Analyst, ensuring operations stay within AWS Free Tier limits while maximizing performance and functionality.

## Features

### 🎯 Free Tier Usage Tracking
- **Real-time monitoring** of Athena query costs and Bedrock token usage
- **Automatic alerts** when approaching Free Tier limits
- **Detailed usage analytics** with cost projections
- **CloudWatch integration** for metrics and monitoring

### 🚦 Intelligent Throttling
- **Smart throttling** near Free Tier limits to prevent overages
- **Priority-based queuing** for critical security operations
- **Graceful degradation** that maintains core functionality
- **Emergency controls** to prevent cost overruns

### 🗄️ Performance Caching
- **Query result caching** to reduce expensive Athena operations
- **AI insight caching** to minimize Bedrock API calls
- **Intelligent cache management** with LRU eviction
- **Persistent caching** across application restarts

### 🤖 Model Selection Optimization
- **Automatic model selection** based on query complexity
- **Cost-effectiveness optimization** for different use cases
- **Budget-aware recommendations** for Free Tier usage
- **Performance vs. cost balancing**

## Quick Start

```python
from cost_optimization import CostOptimizer
from config.aws_config import create_aws_clients

# Initialize AWS clients
aws_clients = create_aws_clients()

# Create cost optimizer
optimizer = CostOptimizer(aws_clients, cache_size_mb=100)

# Execute optimized Athena query
result = await optimizer.execute_athena_query(
    query="SELECT * FROM security_events WHERE severity = 'HIGH'",
    parameters={"timeframe": "last_24h"},
    use_cache=True
)

# Execute optimized Bedrock inference
insight = await optimizer.execute_bedrock_inference(
    prompt="Analyze these security events for threats",
    query_complexity="moderate",
    accuracy_priority="balanced",
    use_cache=True
)

# Get optimization dashboard
dashboard = optimizer.get_optimization_dashboard()
print(f"Free Tier Usage: {dashboard['cost_analysis']['free_tier_status']}")
```

## Components

### UsageTracker
Monitors AWS service usage against Free Tier limits:

```python
from cost_optimization import UsageTracker

tracker = UsageTracker(aws_clients)

# Get current usage for a service
usage = tracker.get_current_usage(ServiceType.ATHENA)
usage_percentage = usage.get_usage_percentage(tracker.limits)

# Get optimization recommendations
recommendations = tracker.get_optimization_recommendations()
```

### CacheManager
Intelligent caching for query results and AI insights:

```python
from cost_optimization import CacheManager

cache = CacheManager(max_size_mb=50, default_ttl_seconds=3600)

# Cache query result
cache.cache_query_result(query, parameters, result)

# Retrieve from cache
cached_result = cache.get_cached_query_result(query, parameters)

# Cache AI insight
cache.cache_ai_insight(input_data, model_id, insight)
```

### ModelSelector
Optimizes Bedrock model selection for cost and performance:

```python
from cost_optimization import ModelSelector
from cost_optimization.models import ModelSelectionCriteria

selector = ModelSelector()

criteria = ModelSelectionCriteria(
    query_complexity="moderate",
    response_length_required="medium", 
    accuracy_priority="balanced",
    available_budget_tokens=5000
)

optimal_model = selector.select_model(criteria)
```

### ThrottlingManager
Manages intelligent throttling based on usage:

```python
from cost_optimization import ThrottlingManager

manager = ThrottlingManager(usage_tracker)

# Execute with throttling protection
result = await manager.execute_with_throttling(
    ServiceType.BEDROCK,
    my_function,
    RequestPriority.HIGH,
    *args, **kwargs
)
```

## Configuration

### Free Tier Limits
Default limits are configured for AWS Free Tier:

```python
from cost_optimization.models import FreeTierLimits

limits = FreeTierLimits(
    athena_data_scanned_gb_monthly=10240.0,  # 10 TB
    bedrock_input_tokens_monthly=25000,
    bedrock_output_tokens_monthly=25000,
    s3_storage_gb_monthly=5.0,
    s3_get_requests_monthly=20000,
    s3_put_requests_monthly=2000
)
```

### Throttling Configuration
Customize throttling behavior:

```python
from cost_optimization.models import ThrottlingConfig

config = ThrottlingConfig(
    light_throttle_threshold=60.0,    # 60% of Free Tier
    moderate_throttle_threshold=75.0,  # 75% of Free Tier
    heavy_throttle_threshold=85.0,     # 85% of Free Tier
    block_threshold=95.0,              # 95% of Free Tier
    light_throttle_delay_seconds=1.0,
    moderate_throttle_delay_seconds=3.0,
    heavy_throttle_delay_seconds=10.0
)
```

## Monitoring and Alerts

### CloudWatch Integration
The system publishes metrics to CloudWatch:

- `AISecurityAnalyst/Usage/FreeTierUsagePercentage` - Usage percentage by service
- `AISecurityAnalyst/Cost/EstimatedCostUSD` - Estimated costs by service

### Dashboard
Get comprehensive optimization status:

```python
dashboard = optimizer.get_optimization_dashboard()

# Usage summary by service
for service, metrics in dashboard['usage_summary'].items():
    print(f"{service}: {metrics['usage_percentage']:.1f}% of Free Tier")

# Cache performance
cache_stats = dashboard['cache_performance']['stats']
print(f"Cache hit rate: {cache_stats['hit_rate']:.1f}%")

# Cost projections
projections = optimizer.get_cost_projections(days_ahead=30)
print(f"Projected monthly cost: ${projections['total_projected_cost']:.2f}")
```

## Emergency Controls

### Automatic Emergency Mode
When usage approaches 95% of Free Tier limits:

```python
# Automatically triggered emergency controls
emergency_response = await optimizer.emergency_cost_control()

# Manual emergency activation
optimizer.throttling_manager.set_emergency_mode(True)
```

Emergency mode:
- Enables heavy throttling for all services
- Blocks non-critical requests
- Optimizes cache to reduce resource usage
- Provides immediate cost reduction recommendations

## Best Practices

### 1. Cache Strategy
- Enable caching for all repeated queries
- Use appropriate TTL values (longer for expensive operations)
- Monitor cache hit rates and optimize accordingly

### 2. Model Selection
- Use Claude 3 Haiku for simple queries (most cost-effective)
- Reserve Claude 3 Sonnet/Opus for complex analysis requiring higher accuracy
- Consider query complexity when selecting models

### 3. Query Optimization
- Use columnar formats (Parquet) for Athena queries
- Implement proper partitioning to reduce data scanned
- Cache frequently accessed query results

### 4. Monitoring
- Set up CloudWatch alarms for usage thresholds
- Review optimization recommendations regularly
- Monitor cost projections to avoid surprises

## Free Tier Optimization Tips

1. **Maximize Caching**: Cache results aggressively to reduce API calls
2. **Smart Model Selection**: Use the cheapest model that meets accuracy requirements
3. **Query Optimization**: Minimize data scanned in Athena queries
4. **Batch Operations**: Group similar operations together when possible
5. **Monitor Usage**: Check usage regularly and adjust behavior proactively

## Demo

Run the cost optimization demo to see all features in action:

```bash
cd src/python/aws_bedrock_athena_ai
python demo_cost_optimization.py
```

The demo showcases:
- Intelligent model selection for different scenarios
- Caching effectiveness for queries and AI insights
- Integrated cost optimization dashboard
- Emergency cost control measures

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Application   │───▶│  CostOptimizer   │───▶│  AWS Services   │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  UsageTracker    │
                    │  CacheManager    │
                    │  ModelSelector   │
                    │  ThrottlingMgr   │
                    └──────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │   CloudWatch     │
                    │   Monitoring     │
                    └──────────────────┘
```

The cost optimization system sits between your application and AWS services, providing transparent optimization while maintaining full functionality within Free Tier constraints.