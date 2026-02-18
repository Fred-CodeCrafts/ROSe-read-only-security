#!/usr/bin/env python3
"""
Simple demonstration of the onboarding system components.

This script demonstrates the key onboarding features without requiring
full AWS integration, perfect for showcasing the capabilities.
"""

import json
import sys
from pathlib import Path

# Add the current directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent))

from onboarding.format_detector import DataFormatDetector
from onboarding.sample_data import SampleDataGenerator
from onboarding.tutorial_system import TutorialSystem
from onboarding.demo_scenarios import DemoScenarios
from onboarding.models import DataFormat, OnboardingSession, OnboardingProgress, OnboardingStage


def print_banner():
    """Print welcome banner"""
    print("=" * 80)
    print("🤖 AI Security Analyst - Onboarding System Demo")
    print("=" * 80)
    print()
    print("This demo showcases the onboarding system that helps new users")
    print("get immediate value from the AI Security Analyst in 5 minutes.")
    print()


def demo_format_detection():
    """Demonstrate automatic format detection"""
    print("🔍 DEMO 1: Automatic Data Format Detection")
    print("-" * 50)
    print()
    
    detector = DataFormatDetector()
    generator = SampleDataGenerator()
    
    # Test different formats
    formats_to_test = [
        (DataFormat.JSON, "sample_security.json"),
        (DataFormat.CSV, "security_logs.csv"),
        (DataFormat.CLOUDTRAIL, "cloudtrail_logs.json"),
        (DataFormat.SYSLOG, "system.log")
    ]
    
    for data_format, filename in formats_to_test:
        print(f"Testing format detection for {data_format.value}:")
        
        # Generate sample data
        sample_content = generator.generate_sample_dataset(
            format_type=data_format,
            record_count=5,
            include_threats=False
        )
        
        # Show first few lines
        lines = sample_content.split('\n')[:2]
        print(f"   Sample data: {lines[0][:60]}...")
        
        # Detect format
        detection_result = detector.detect_format(sample_content, filename)
        
        print(f"   ✅ Detected: {detection_result.detected_format.value}")
        print(f"   ✅ Confidence: {detection_result.confidence_score:.2f}")
        print(f"   ✅ Fields found: {len(detection_result.schema_preview.get('fields', []))}")
        
        if detection_result.recommendations:
            print(f"   💡 Recommendation: {detection_result.recommendations[0]}")
        
        print()


def demo_sample_data_generation():
    """Demonstrate sample data generation"""
    print("🔧 DEMO 2: Realistic Sample Data Generation")
    print("-" * 50)
    print()
    
    generator = SampleDataGenerator()
    
    # Generate sample security data with threats
    print("Generating sample security data with suspicious activities...")
    sample_data = generator.generate_sample_dataset(
        format_type=DataFormat.JSON,
        record_count=10,
        include_threats=True
    )
    
    # Show sample records
    lines = sample_data.strip().split('\n')
    print(f"Generated {len(lines)} security events:")
    print()
    
    for i, line in enumerate(lines[:3], 1):
        data = json.loads(line)
        print(f"   {i}. {data['timestamp']} - {data['event_type']} by {data['user']} ({data['severity']})")
    
    print("   ... (7 more events)")
    print()
    
    # Generate critical issues
    print("Sample critical security issues found:")
    critical_issues = generator.generate_critical_issues_sample()
    
    for issue in critical_issues:
        print(f"   🚨 {issue['title']} ({issue['severity']})")
        print(f"      {issue['description']}")
        print(f"      Action: {issue['recommendation']}")
        print()


def demo_tutorials():
    """Demonstrate the tutorial system"""
    print("🎓 DEMO 3: Interactive Tutorial System")
    print("-" * 50)
    print()
    
    tutorial_system = TutorialSystem()
    
    # Show available tutorials
    print("Available interactive tutorials:")
    tutorials = tutorial_system.get_available_tutorials()
    
    for i, tutorial in enumerate(tutorials, 1):
        print(f"   {i}. {tutorial.title}")
        print(f"      Duration: {tutorial.estimated_duration_minutes} minutes")
        print(f"      Level: {tutorial.difficulty_level}")
        print(f"      Description: {tutorial.description}")
        print()
    
    # Demonstrate a tutorial step
    basic_tutorial = tutorials[0]  # Basic questions tutorial
    print(f"Sample from '{basic_tutorial.title}' tutorial:")
    print()
    
    first_step = basic_tutorial.steps[0]
    print(f"📖 Step: {first_step.title}")
    print(f"Description: {first_step.description}")
    print(f"Example Question: '{first_step.example_question}'")
    print(f"Expected Outcome: {first_step.expected_outcome}")
    print()
    
    if first_step.hints:
        print("💡 Hints:")
        for hint in first_step.hints:
            print(f"   • {hint}")
        print()


def demo_scenarios():
    """Demonstrate the scenario system"""
    print("🎬 DEMO 4: Pre-built Demonstration Scenarios")
    print("-" * 50)
    print()
    
    scenarios = DemoScenarios()
    
    # Show available scenarios
    print("Available demonstration scenarios:")
    available_scenarios = scenarios.get_available_scenarios()
    
    for i, scenario in enumerate(available_scenarios, 1):
        print(f"   {i}. {scenario.title}")
        print(f"      Duration: {scenario.estimated_duration_minutes} minutes")
        print(f"      Type: {scenario.scenario_type}")
        print(f"      Business Value: {scenario.business_value}")
        print()
    
    # Demonstrate breach detection scenario
    breach_scenario = available_scenarios[0]  # Breach detection
    print(f"Sample from '{breach_scenario.title}' scenario:")
    print()
    
    # Create mock session for demo
    progress = OnboardingProgress(user_id="demo_user", current_stage=OnboardingStage.DEMO_SCENARIOS)
    session = OnboardingSession(session_id="demo_session", progress=progress)
    
    scenario_context = scenarios.start_scenario(breach_scenario.scenario_id, session)
    
    print("🔍 Key Questions in this scenario:")
    for i, question in enumerate(breach_scenario.key_questions, 1):
        print(f"   {i}. '{question}'")
    print()
    
    print("🤖 Expected AI Insights:")
    for i, insight in enumerate(breach_scenario.expected_insights, 1):
        print(f"   {i}. {insight}")
    print()
    
    # Show sample scenario data
    sample_data = scenario_context['sample_data']
    if 'attack_timeline' in sample_data:
        print("📅 Sample Attack Timeline:")
        for event in sample_data['attack_timeline'][:3]:
            print(f"   • {event['timestamp']}: {event['event']} ({event['severity']})")
        print()


def demo_business_value():
    """Demonstrate the business value proposition"""
    print("💰 DEMO 5: Business Value Demonstration")
    print("-" * 50)
    print()
    
    print("AI Security Analyst delivers immediate business value:")
    print()
    
    value_props = [
        {
            "capability": "5-Minute Security Assessment",
            "traditional_time": "2-4 weeks",
            "ai_time": "5 minutes",
            "cost_savings": "$50,000 - $200,000 per assessment"
        },
        {
            "capability": "Threat Detection & Analysis",
            "traditional_time": "Hours to days",
            "ai_time": "Seconds",
            "cost_savings": "Prevent $4.45M average breach cost"
        },
        {
            "capability": "Compliance Auditing",
            "traditional_time": "Weeks",
            "ai_time": "Minutes",
            "cost_savings": "$100,000 - $500,000 per audit"
        }
    ]
    
    for prop in value_props:
        print(f"📈 {prop['capability']}:")
        print(f"   Traditional: {prop['traditional_time']}")
        print(f"   AI-Powered: {prop['ai_time']}")
        print(f"   Value: {prop['cost_savings']}")
        print()
    
    print("🎯 Key Benefits:")
    print("   ✅ Turn any organization into a security powerhouse")
    print("   ✅ Get enterprise-grade security analysis at startup costs")
    print("   ✅ 24/7 AI security analyst that never sleeps")
    print("   ✅ Immediate insights vs. months of traditional setup")
    print()


def main():
    """Run the complete onboarding demonstration"""
    print_banner()
    
    try:
        # Demo 1: Format detection
        demo_format_detection()
        
        input("Press Enter to continue to sample data generation demo...")
        print()
        
        # Demo 2: Sample data generation
        demo_sample_data_generation()
        
        input("Press Enter to continue to tutorials demo...")
        print()
        
        # Demo 3: Tutorial system
        demo_tutorials()
        
        input("Press Enter to continue to scenarios demo...")
        print()
        
        # Demo 4: Scenario system
        demo_scenarios()
        
        input("Press Enter to see business value summary...")
        print()
        
        # Demo 5: Business value
        demo_business_value()
        
        # Completion
        print("🎉 ONBOARDING SYSTEM DEMO COMPLETED!")
        print("=" * 60)
        print()
        print("This demonstration showcased the key components of the")
        print("AI Security Analyst onboarding system:")
        print()
        print("✅ Automatic data format detection and analysis")
        print("✅ Realistic sample data generation with threats")
        print("✅ Interactive tutorials for learning the system")
        print("✅ Pre-built scenarios showing real-world value")
        print("✅ Clear business value proposition")
        print()
        print("The onboarding system ensures new users can:")
        print("• Get immediate value within 5 minutes")
        print("• Learn through hands-on tutorials")
        print("• See real-world applications via scenarios")
        print("• Understand the business impact")
        print()
        print("Ready to implement the full AI Security Analyst?")
        print("The onboarding system is complete and ready for integration!")
        
    except KeyboardInterrupt:
        print("\n⚠️ Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()