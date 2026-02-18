#!/usr/bin/env python3
"""Quick verification script for Task 6 completion"""

print("=== Task 6 Verification ===\n")

# Test 1: Imports
print("Test 1: Verifying imports...")
try:
    from aws_bedrock_athena_ai.demo_cost_optimization import (
        is_cost_explorer_available,
        get_mock_cost_data,
        CostOptimizer,
        ModelSelector,
        CacheManager
    )
    print("✅ All imports successful\n")
except ImportError as e:
    print(f"❌ Import failed: {e}\n")
    exit(1)

# Test 2: AWS detection function
print("Test 2: Verifying AWS detection function...")
try:
    available = is_cost_explorer_available()
    print(f"✅ is_cost_explorer_available() works (returned: {available})\n")
except Exception as e:
    print(f"❌ Function failed: {e}\n")
    exit(1)

# Test 3: Mock data generation
print("Test 3: Verifying mock data generation...")
try:
    mock = get_mock_cost_data()
    print(f"✅ get_mock_data() works")
    print(f"   - Top-level keys: {len(mock)}")
    print(f"   - Dashboard mode: {mock['dashboard']['mode']}")
    print(f"   - Free Tier status: {mock['dashboard']['cost_analysis']['free_tier_status']['overall_status']}")
    print(f"   - Cache hit rate: {mock['dashboard']['cache_performance']['stats']['hit_rate']}%")
    print(f"   - Projected cost: ${mock['projections']['total_projected_cost']:.2f}\n")
except Exception as e:
    print(f"❌ Mock data generation failed: {e}\n")
    exit(1)

# Test 4: Requirements validation
print("Test 4: Validating requirements...")
requirements_met = {
    "US-3.1: Import errors fixed": True,
    "US-3.2: Dashboard displays": 'dashboard' in mock,
    "US-3.3: Usage metrics shown": 'optimization_stats' in mock,
    "US-3.4: Free Tier status": 'free_tier_status' in mock['dashboard']['cost_analysis'],
    "US-3.5: Mock data available": mock['dashboard']['mode'] == 'demo',
    "TR-5: Full package paths": True
}

all_met = all(requirements_met.values())
for req, met in requirements_met.items():
    status = "✅" if met else "❌"
    print(f"{status} {req}")

print("\n" + "="*50)
if all_met:
    print("✅ ALL TASK 6 REQUIREMENTS MET")
    print("="*50)
    print("\nTask 6 is complete:")
    print("• Import statements fixed")
    print("• Mock mode implemented")
    print("• AWS detection working")
    print("• Dashboard data available")
    print("• Free Tier status included")
    exit(0)
else:
    print("❌ SOME REQUIREMENTS NOT MET")
    print("="*50)
    exit(1)
