#!/usr/bin/env python3
"""
Demonstration script for the AI Security Analyst onboarding system.

This script showcases the quick-start capabilities, tutorials, and demo scenarios
that help new users get immediate value from the system.
"""

import json
import time
from datetime import datetime
from pathlib import Path

from onboarding import QuickStartManager, TutorialSystem, DemoScenarios
from onboarding.models import DataFormat


def print_banner():
    """Print welcome banner"""
    print("=" * 80)
    print("🤖 AI Security Analyst in Your Pocket - Onboarding Demo")
    print("=" * 80)
    print()
    print("Welcome! This demo shows how new users can get immediate value")
    print("from the AI Security Analyst in just 5 minutes.")
    print()


def demo_quick_start():
    """Demonstrate the quick-start onboarding process"""
    print("🚀 DEMO: Quick-Start Onboarding Process")
    print("-" * 50)
    print()
    
    # Initialize quick start manager
    quick_start = QuickStartManager()
    
    # Start onboarding session
    print("1. Starting onboarding session...")
    session = quick_start.start_onboarding_session("demo_user")
    print(f"   ✅ Session created: {session.session_id}")
    print()
    
    # Generate sample data
    print("2. Generating realistic sample security data...")
    uploaded_file = quick_start.generate_sample_data_for_demo(
        session,
        data_format=DataFormat.JSON,
        record_count=500
    )
    print(f"   ✅ Generated {uploaded_file.file_size_bytes:,} bytes of sample data")
    print(f"   ✅ Format detected: {uploaded_file.detected_format.value}")
    print(f"   ✅ Confidence: {uploaded_file.confidence_score:.2f}")
    print()
    
    # Perform quick analysis
    print("3. Performing 5-minute security analysis...")
    start_time = time.time()
    analysis_result = quick_start.perform_quick_analysis(session)
    analysis_time = time.time() - start_time
    
    print(f"   ✅ Analysis completed in {analysis_time:.1f} seconds")
    print(f"   ✅ Security Score: {analysis_result.security_score}/100")
    print(f"   ✅ Critical Issues Found: {len(analysis_result.critical_issues)}")
    print()
    
    # Display key findings
    print("📊 KEY FINDINGS:")
    for i, finding in enumerate(analysis_result.key_findings[:3], 1):
        print(f"   {i}. {finding}")
    print()
    
    # Display critical issues
    if analysis_result.critical_issues:
        print("🚨 CRITICAL ISSUES:")
        for issue in analysis_result.critical_issues[:2]:
            print(f"   • {issue['title']} ({issue['severity']})")
            print(f"     {issue['description']}")
        print()
    
    # Display recommendations
    print("💡 IMMEDIATE RECOMMENDATIONS:")
    for i, rec in enumerate(analysis_result.recommendations[:3], 1):
        print(f"   {i}. {rec}")
    print()
    
    return session


def demo_tutorials(session):
    """Demonstrate the tutorial system"""
    print("🎓 DEMO: Interactive Tutorial System")
    print("-" * 50)
    print()
    
    tutorial_system = TutorialSystem()
    
    # Show available tutorials
    print("Available tutorials:")
    tutorials = tutorial_system.get_available_tutorials()
    for i, tutorial in enumerate(tutorials[:3], 1):
        print(f"   {i}. {tutorial.title} ({tutorial.estimated_duration_minutes} min)")
        print(f"      Level: {tutorial.difficulty_level}")
        print(f"      {tutorial.description}")
        print()
    
    # Demonstrate starting a tutorial
    basic_tutorial = tutorials[0]  # Basic questions tutorial
    print(f"Starting tutorial: {basic_tutorial.title}")
    
    started_tutorial = tutorial_system.start_tutorial(basic_tutorial.tutorial_id, session)
    
    # Show first tutorial step
    first_step = started_tutorial.steps[0]
    print(f"\n📖 Tutorial Step: {first_step.title}")
    print(f"Description: {first_step.description}")
    print(f"Example Question: '{first_step.example_question}'")
    print(f"Expected Outcome: {first_step.expected_outcome}")
    print()
    
    # Simulate completing the step
    tutorial_system.complete_tutorial_step(
        basic_tutorial.tutorial_id,
        first_step.step_id,
        session
    )
    print("✅ Tutorial step completed!")
    
    # Show progress
    progress = tutorial_system.get_tutorial_progress(basic_tutorial.tutorial_id, session)
    print(f"Tutorial Progress: {progress['completion_percentage']:.1f}%")
    print()


def demo_scenarios(session):
    """Demonstrate the scenario system"""
    print("🎬 DEMO: Pre-built Demonstration Scenarios")
    print("-" * 50)
    print()
    
    scenarios = DemoScenarios()
    
    # Show available scenarios
    print("Available demonstration scenarios:")
    available_scenarios = scenarios.get_available_scenarios()
    for i, scenario in enumerate(available_scenarios[:3], 1):
        print(f"   {i}. {scenario.title} ({scenario.estimated_duration_minutes} min)")
        print(f"      Type: {scenario.scenario_type}")
        print(f"      {scenario.description}")
        print()
    
    # Demonstrate breach detection scenario
    breach_scenario = available_scenarios[0]  # Breach detection
    print(f"Starting scenario: {breach_scenario.title}")
    
    scenario_context = scenarios.start_scenario(breach_scenario.scenario_id, session)
    
    # Show first scenario step
    first_question = breach_scenario.key_questions[0]
    print(f"\n🔍 Scenario Question: '{first_question}'")
    
    # Complete the first step
    step_result = scenarios.complete_scenario_step(scenario_context, 0, first_question)
    
    print(f"🤖 AI Response: {step_result['ai_response']}")
    print(f"Progress: {step_result['progress']:.1f}%")
    print()
    
    # Show sample data from the scenario
    sample_data = scenario_context['sample_data']
    if 'attack_timeline' in sample_data:
        print("📅 Attack Timeline Preview:")
        for event in sample_data['attack_timeline'][:2]:
            print(f"   • {event['timestamp']}: {event['event']} ({event['severity']})")
        print()


def demo_format_detection():
    """Demonstrate automatic format detection"""
    print("🔍 DEMO: Automatic Data Format Detection")
    print("-" * 50)
    print()
    
    from onboarding.format_detector import DataFormatDetector
    from onboarding.sample_data import SampleDataGenerator
    
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
            record_count=10,
            include_threats=False
        )
        
        # Detect format
        detection_result = detector.detect_format(sample_content, filename)
        
        print(f"   Detected: {detection_result.detected_format.value}")
        print(f"   Confidence: {detection_result.confidence_score:.2f}")
        print(f"   Fields found: {len(detection_result.schema_preview.get('fields', []))}")
        
        if detection_result.recommendations:
            print(f"   Recommendation: {detection_result.recommendations[0]}")
        
        print()


def demo_business_value():
    """Demonstrate the business value proposition"""
    print("💰 DEMO: Business Value Demonstration")
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
        },
        {
            "capability": "Risk Assessment",
            "traditional_time": "Days to weeks",
            "ai_time": "Minutes",
            "cost_savings": "Better risk prioritization = 50% more effective security spend"
        }
    ]
    
    for prop in value_props:
        print(f"📈 {prop['capability']}:")
        print(f"   Traditional: {prop['traditional_time']}")
        print(f"   AI-Powered: {prop['ai_time']}")
        print(f"   Value: {prop['cost_savings']}")
        print()
    
    print("🎯 Total Value Proposition:")
    print("   • Turn any organization into a security powerhouse")
    print("   • Get enterprise-grade security analysis at startup costs")
    print("   • 24/7 AI security analyst that never sleeps")
    print("   • Immediate insights vs. months of traditional setup")
    print()


def main():
    """Run the complete onboarding demonstration"""
    print_banner()
    
    try:
        # Demo 1: Quick-start process
        session = demo_quick_start()
        
        input("Press Enter to continue to tutorials demo...")
        print()
        
        # Demo 2: Tutorial system
        demo_tutorials(session)
        
        input("Press Enter to continue to scenarios demo...")
        print()
        
        # Demo 3: Scenario system
        demo_scenarios(session)
        
        input("Press Enter to continue to format detection demo...")
        print()
        
        # Demo 4: Format detection
        demo_format_detection()
        
        input("Press Enter to see business value summary...")
        print()
        
        # Demo 5: Business value
        demo_business_value()
        
        # Completion
        print("🎉 ONBOARDING DEMO COMPLETED!")
        print("=" * 50)
        print()
        print("This demonstration showed how the AI Security Analyst")
        print("delivers immediate value to new users through:")
        print()
        print("✅ 5-minute quick-start with instant insights")
        print("✅ Interactive tutorials for learning the system")
        print("✅ Pre-built scenarios showing real-world value")
        print("✅ Automatic data format detection")
        print("✅ Clear business value proposition")
        print()
        print("Ready to transform your security posture?")
        print("Start with: python -m aws_bedrock_athena_ai.onboarding.cli start")
        print()
        
    except KeyboardInterrupt:
        print("\n⚠️ Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()