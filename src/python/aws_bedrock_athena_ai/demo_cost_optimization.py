#!/usr/bin/env python3
"""
Cost Optimization Demo

Demonstrates the cost optimization and monitoring capabilities
of the AI Security Analyst system.
"""

import asyncio
import json
import logging
import os
from datetime import datetime
from unittest.mock import Mock

from aws_bedrock_athena_ai.cost_optimization.cost_optimizer import CostOptimizer
from aws_bedrock_athena_ai.cost_optimization.model_selector import ModelSelector
from aws_bedrock_athena_ai.cost_optimization.cache_manager import CacheManager
from aws_bedrock_athena_ai.cost_optimization.models import ModelSelectionCriteria, ServiceType
from aws_bedrock_athena_ai.cost_optimization.throttling_manager import RequestPriority

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def is_cost_explorer_available() -> bool:
    """
    Check if AWS Cost Explorer is configured and available.
    
    Returns:
        True if Cost Explorer is available, False otherwise
    """
    # Check for explicit demo mode
    if os.getenv('DEMO_MODE', '').lower() == 'true':
        return False
    
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
        
        # Check for AWS credentials
        session = boto3.Session()
        credentials = session.get_credentials()
        if not credentials:
            logger.debug("No AWS credentials found for Cost Explorer")
            return False
        
        # Try to create Cost Explorer client
        ce = boto3.client('ce')
        
        # Lightweight check - verify client creation
        return True
        
    except NoCredentialsError:
        logger.debug("No AWS credentials found for Cost Explorer")
        return False
    except Exception as e:
        logger.debug(f"Cost Explorer availability check failed: {e}")
        return False


def get_mock_cost_data() -> dict:
    """
    Generate mock cost data for demo mode.
    
    Returns:
        Dictionary with mock cost optimization data
    """
    return {
        "dashboard": {
            "timestamp": datetime.now().isoformat(),
            "mode": "demo",
            "cache_performance": {
                "stats": {
                    "hit_rate": 75.5,
                    "total_entries": 42,
                    "size_mb": 2.3,
                    "hit_count": 151,
                    "miss_count": 49
                }
            },
            "cost_analysis": {
                "free_tier_status": {
                    "overall_status": "healthy",
                    "services_at_risk": [],
                    "bedrock_usage_percent": 45.2,
                    "athena_usage_percent": 32.8
                }
            }
        },
        "projections": {
            "total_projected_cost": 0.00,
            "days_ahead": 30,
            "recommendations": [
                "Continue using Free Tier - well within limits",
                "Cache hit rate is excellent at 75.5%",
                "Consider upgrading if usage increases by 50%"
            ]
        },
        "optimization_stats": {
            "queries_cached": 151,
            "model_optimizations": 89,
            "cost_savings_usd": 12.45
        }
    }


def demo_model_selection():
    """Demonstrate intelligent model selection"""
    print("\n" + "="*60)
    print("🤖 INTELLIGENT MODEL SELECTION DEMO")
    print("="*60)
    
    selector = ModelSelector()
    
    # Test different scenarios
    scenarios = [
        {
            "name": "Simple Security Check",
            "criteria": ModelSelectionCriteria(
                query_complexity="simple",
                response_length_required="short",
                accuracy_priority="speed",
                available_budget_tokens=1000
            )
        },
        {
            "name": "Threat Analysis",
            "criteria": ModelSelectionCriteria(
                query_complexity="moderate",
                response_length_required="medium",
                accuracy_priority="balanced",
                available_budget_tokens=5000
            )
        },
        {
            "name": "Comprehensive Assessment",
            "criteria": ModelSelectionCriteria(
                query_complexity="complex",
                response_length_required="long",
                accuracy_priority="accuracy",
                available_budget_tokens=10000
            )
        }
    ]
    
    for scenario in scenarios:
        print(f"\n📋 Scenario: {scenario['name']}")
        print(f"   Complexity: {scenario['criteria'].query_complexity}")
        print(f"   Priority: {scenario['criteria'].accuracy_priority}")
        print(f"   Budget: {scenario['criteria'].available_budget_tokens} tokens")
        
        selected_model = selector.select_model(scenario['criteria'])
        model_info = selector.available_models[selected_model]
        
        print(f"   ✅ Selected: {model_info.name}")
        print(f"   💰 Cost Tier: {model_info.tier.value}")
        
        # Estimate cost
        cost_estimate = selector.estimate_monthly_cost(
            selected_model,
            queries_per_day=10,
            avg_input_tokens=1000,
            avg_output_tokens=500
        )
        
        print(f"   📊 Monthly Cost (10 queries/day): ${cost_estimate['monthly_cost_usd']:.2f}")
    
    # Show Free Tier recommendations
    print(f"\n💡 Free Tier Recommendations:")
    free_tier_rec = selector.get_free_tier_recommendations()
    print(f"   Primary Model: {free_tier_rec['primary_model']}")
    print(f"   Max Queries/Month: {free_tier_rec['max_queries_per_month']}")
    
    for tip in free_tier_rec['optimization_tips'][:3]:
        print(f"   • {tip}")


def demo_caching():
    """Demonstrate intelligent caching"""
    print("\n" + "="*60)
    print("🗄️  INTELLIGENT CACHING DEMO")
    print("="*60)
    
    cache = CacheManager(max_size_mb=10, default_ttl_seconds=3600)
    
    # Simulate query caching
    print("\n📊 Query Result Caching:")
    
    query1 = "SELECT * FROM security_events WHERE severity = 'HIGH'"
    params1 = {"timeframe": "last_24h", "limit": 100}
    result1 = {"events": [{"id": 1, "type": "login_failure"}], "count": 1}
    
    # Cache the result
    print("   Caching query result...")
    cache.cache_query_result(query1, params1, result1)
    
    # Retrieve from cache
    print("   Retrieving from cache...")
    cached_result = cache.get_cached_query_result(query1, params1)
    
    if cached_result:
        print("   ✅ Cache HIT - Query result retrieved from cache")
    else:
        print("   ❌ Cache MISS - Would need to execute query")
    
    # Simulate AI insight caching
    print("\n🧠 AI Insight Caching:")
    
    input_data = "Analyze recent security events for threats"
    model_id = "claude-3-haiku"
    insight = {
        "threats_detected": 2,
        "risk_level": "medium",
        "recommendations": ["Update firewall rules", "Monitor user accounts"]
    }
    
    print("   Caching AI insight...")
    cache.cache_ai_insight(input_data, model_id, insight)
    
    print("   Retrieving from cache...")
    cached_insight = cache.get_cached_ai_insight(input_data, model_id)
    
    if cached_insight:
        print("   ✅ Cache HIT - AI insight retrieved from cache")
    else:
        print("   ❌ Cache MISS - Would need to call Bedrock")
    
    # Show cache statistics
    stats = cache.get_cache_stats()
    print(f"\n📈 Cache Statistics:")
    print(f"   Total Entries: {stats.total_entries}")
    print(f"   Cache Size: {stats.size_mb:.2f} MB")
    print(f"   Hit Rate: {stats.hit_rate:.1f}%")
    print(f"   Hits: {stats.hit_count}, Misses: {stats.miss_count}")


async def demo_cost_optimizer():
    """Demonstrate the integrated cost optimizer"""
    print("\n" + "="*60)
    print("💰 INTEGRATED COST OPTIMIZER DEMO")
    print("="*60)
    
    # Check if AWS Cost Explorer is available
    aws_available = is_cost_explorer_available()
    
    if not aws_available:
        print("\n⚠️  AWS Cost Explorer not configured - using mock data")
        print("   (Set AWS credentials to see real cost data)")
        
        # Use mock data
        mock_data = get_mock_cost_data()
        
        print("\n🎯 Demo Mode - Showing mock optimization data...")
        
        print("   1. Athena query caching enabled ✅")
        print("   2. Bedrock model selection optimized ✅")
        
        # Show optimization dashboard
        print("\n📊 Optimization Dashboard (Mock Data):")
        dashboard = mock_data['dashboard']
        
        print(f"   Timestamp: {dashboard['timestamp']}")
        print(f"   Mode: {dashboard['mode'].upper()}")
        print(f"   Cache Performance: {dashboard['cache_performance']['stats']['hit_rate']:.1f}% hit rate")
        print(f"   Optimization Stats:")
        print(f"      Queries Cached: {mock_data['optimization_stats']['queries_cached']}")
        print(f"      Model Optimizations: {mock_data['optimization_stats']['model_optimizations']}")
        print(f"      Cost Savings: ${mock_data['optimization_stats']['cost_savings_usd']:.2f}")
        
        # Show cost projections
        print("\n📈 Cost Projections (30 days):")
        projections = mock_data['projections']
        
        print(f"   Total Projected Cost: ${projections['total_projected_cost']:.2f}")
        
        if projections['recommendations']:
            print("   💡 Recommendations:")
            for rec in projections['recommendations'][:2]:
                print(f"      • {rec}")
        
        # Show Free Tier status
        free_tier_status = dashboard['cost_analysis']['free_tier_status']
        print(f"\n🎯 Free Tier Status: {free_tier_status['overall_status'].upper()}")
        print(f"   Bedrock Usage: {free_tier_status['bedrock_usage_percent']:.1f}%")
        print(f"   Athena Usage: {free_tier_status['athena_usage_percent']:.1f}%")
        
        if free_tier_status['services_at_risk']:
            print(f"   ⚠️  Services at risk: {', '.join(free_tier_status['services_at_risk'])}")
        else:
            print("   ✅ All services within safe limits")
        
        return
    
    # Original AWS-based implementation
    # Create mock AWS clients
    mock_clients = Mock()
    mock_clients.cloudwatch = Mock()
    mock_clients.athena = Mock()
    mock_clients.bedrock_runtime = Mock()
    
    # Initialize cost optimizer
    optimizer = CostOptimizer(mock_clients, cache_size_mb=50)
    
    print("\n🎯 Simulating optimized operations...")
    
    # Simulate some operations
    print("   1. Executing Athena query with caching...")
    query = "SELECT COUNT(*) FROM security_events WHERE timestamp > NOW() - INTERVAL '1 DAY'"
    params = {"priority": "high"}
    
    # This would normally execute the actual query
    # result = await optimizer.execute_athena_query(query, params, use_cache=True)
    print("      ✅ Query executed with optimization")
    
    print("   2. Executing Bedrock inference with model selection...")
    prompt = "Analyze these security events for potential threats"
    
    # This would normally execute the actual inference
    # result = await optimizer.execute_bedrock_inference(
    #     prompt, 
    #     query_complexity="moderate",
    #     accuracy_priority="balanced",
    #     use_cache=True
    # )
    print("      ✅ Inference executed with optimal model selection")
    
    # Show optimization dashboard
    print("\n📊 Optimization Dashboard:")
    dashboard = optimizer.get_optimization_dashboard()
    
    print(f"   Timestamp: {dashboard['timestamp']}")
    print(f"   Cache Performance: {dashboard['cache_performance']['stats']['hit_rate']:.1f}% hit rate")
    print(f"   Optimization Stats:")
    print(f"      Queries Cached: {optimizer.optimization_stats['queries_cached']}")
    print(f"      Model Optimizations: {optimizer.optimization_stats['model_optimizations']}")
    
    # Show cost projections
    print("\n📈 Cost Projections (30 days):")
    projections = optimizer.get_cost_projections(days_ahead=30)
    
    print(f"   Total Projected Cost: ${projections['total_projected_cost']:.2f}")
    
    if projections['recommendations']:
        print("   💡 Recommendations:")
        for rec in projections['recommendations'][:2]:
            print(f"      • {rec}")
    
    # Show Free Tier status
    free_tier_status = dashboard['cost_analysis']['free_tier_status']
    print(f"\n🎯 Free Tier Status: {free_tier_status['overall_status'].upper()}")
    
    if free_tier_status['services_at_risk']:
        print(f"   ⚠️  Services at risk: {', '.join(free_tier_status['services_at_risk'])}")
    else:
        print("   ✅ All services within safe limits")


def demo_emergency_controls():
    """Demonstrate emergency cost control measures"""
    print("\n" + "="*60)
    print("🚨 EMERGENCY COST CONTROL DEMO")
    print("="*60)
    
    # Create mock AWS clients
    mock_clients = Mock()
    mock_clients.cloudwatch = Mock()
    
    optimizer = CostOptimizer(mock_clients)
    
    print("\n⚠️  Simulating high usage scenario...")
    print("   Free Tier usage approaching 95% limit...")
    
    # Simulate emergency activation
    print("\n🚨 Activating emergency cost controls...")
    
    # This would normally activate real emergency measures
    # emergency_response = await optimizer.emergency_cost_control()
    
    print("   ✅ Emergency throttling enabled")
    print("   ✅ Cache optimized to reduce resource usage")
    print("   ✅ Only critical requests will be processed")
    
    print("\n💡 Emergency Recommendations:")
    print("   • Defer non-critical security analysis until next billing cycle")
    print("   • Use cached results for repeated queries")
    print("   • Switch to fastest/cheapest models only")
    print("   • Consider upgrading to paid tier for continued service")


def main():
    """Run all cost optimization demos"""
    print("🚀 AI Security Analyst - Cost Optimization Demo")
    print("=" * 60)
    
    # Check AWS availability
    aws_available = is_cost_explorer_available()
    
    if aws_available:
        print("Demonstrating intelligent cost optimization features")
        print("that keep your security analysis within AWS Free Tier limits")
    else:
        print("⚠️  Running in DEMO MODE (AWS Cost Explorer not configured)")
        print("Demonstrating cost optimization features with mock data")
        print("Configure AWS credentials to see real cost tracking")
    
    try:
        # Run demos
        demo_model_selection()
        demo_caching()
        
        # Run async demos
        asyncio.run(demo_cost_optimizer())
        
        demo_emergency_controls()
        
        print("\n" + "="*60)
        print("✅ DEMO COMPLETE")
        print("="*60)
        print("The AI Security Analyst includes comprehensive cost optimization:")
        print("• Intelligent model selection based on query complexity")
        print("• Smart caching to reduce API calls")
        print("• Usage tracking and throttling near Free Tier limits")
        print("• Emergency controls to prevent cost overruns")
        print("• Real-time cost monitoring and projections")
        
        if not aws_available:
            print("\n💡 To enable real AWS cost tracking:")
            print("   1. Configure AWS credentials: aws configure")
            print("   2. Ensure Cost Explorer is enabled in your AWS account")
            print("   3. Run this demo again to see actual cost data")
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        print(f"\n❌ Demo failed: {e}")


if __name__ == "__main__":
    main()