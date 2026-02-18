#!/usr/bin/env python3
"""
Test script for cost optimization demo mock mode
"""

import os
import sys

# Set demo mode
os.environ['DEMO_MODE'] = 'true'

from aws_bedrock_athena_ai.demo_cost_optimization import (
    is_cost_explorer_available,
    get_mock_cost_data
)


def test_cost_explorer_detection():
    """Test that Cost Explorer detection works"""
    print("Testing Cost Explorer detection...")
    
    # Should return False in demo mode
    available = is_cost_explorer_available()
    assert available == False, "Cost Explorer should not be available in demo mode"
    
    print("✅ Cost Explorer detection works correctly")


def test_mock_data_generation():
    """Test that mock data is generated correctly"""
    print("\nTesting mock data generation...")
    
    mock_data = get_mock_cost_data()
    
    # Verify structure
    assert 'dashboard' in mock_data, "Mock data should have dashboard"
    assert 'projections' in mock_data, "Mock data should have projections"
    assert 'optimization_stats' in mock_data, "Mock data should have optimization_stats"
    
    # Verify dashboard structure
    dashboard = mock_data['dashboard']
    assert 'timestamp' in dashboard, "Dashboard should have timestamp"
    assert 'mode' in dashboard, "Dashboard should have mode"
    assert dashboard['mode'] == 'demo', "Mode should be 'demo'"
    assert 'cache_performance' in dashboard, "Dashboard should have cache_performance"
    assert 'cost_analysis' in dashboard, "Dashboard should have cost_analysis"
    
    # Verify Free Tier status
    free_tier = dashboard['cost_analysis']['free_tier_status']
    assert 'overall_status' in free_tier, "Free Tier should have overall_status"
    assert 'services_at_risk' in free_tier, "Free Tier should have services_at_risk"
    assert 'bedrock_usage_percent' in free_tier, "Free Tier should have bedrock_usage_percent"
    assert 'athena_usage_percent' in free_tier, "Free Tier should have athena_usage_percent"
    
    # Verify projections
    projections = mock_data['projections']
    assert 'total_projected_cost' in projections, "Projections should have total_projected_cost"
    assert 'recommendations' in projections, "Projections should have recommendations"
    assert len(projections['recommendations']) > 0, "Should have at least one recommendation"
    
    # Verify optimization stats
    stats = mock_data['optimization_stats']
    assert 'queries_cached' in stats, "Stats should have queries_cached"
    assert 'model_optimizations' in stats, "Stats should have model_optimizations"
    assert 'cost_savings_usd' in stats, "Stats should have cost_savings_usd"
    
    print("✅ Mock data generation works correctly")
    print(f"   - Dashboard mode: {dashboard['mode']}")
    print(f"   - Cache hit rate: {dashboard['cache_performance']['stats']['hit_rate']:.1f}%")
    print(f"   - Free Tier status: {free_tier['overall_status']}")
    print(f"   - Projected cost: ${projections['total_projected_cost']:.2f}")


def main():
    """Run all tests"""
    print("="*60)
    print("Testing Cost Optimization Demo Mock Mode")
    print("="*60)
    
    try:
        test_cost_explorer_detection()
        test_mock_data_generation()
        
        print("\n" + "="*60)
        print("✅ ALL TESTS PASSED")
        print("="*60)
        print("\nMock mode is working correctly:")
        print("• Cost Explorer detection works")
        print("• Mock data generation works")
        print("• Dashboard structure is correct")
        print("• Free Tier status is included")
        print("• Cost projections are available")
        
        return 0
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return 1
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
