"""
Command-line interface for the onboarding system.

This module provides CLI commands for managing the onboarding experience,
including quick-start setup, tutorials, and demo scenarios.
"""

import argparse
import json
import sys
import logging
from pathlib import Path
from typing import Optional

from aws_bedrock_athena_ai.onboarding.quick_start import QuickStartManager
from aws_bedrock_athena_ai.onboarding.tutorial_system import TutorialSystem
from aws_bedrock_athena_ai.onboarding.demo_scenarios import DemoScenarios
from aws_bedrock_athena_ai.onboarding.models import DataFormat, OnboardingStage
from aws_bedrock_athena_ai.config import AWSConfig

logger = logging.getLogger(__name__)


class OnboardingCLI:
    """Command-line interface for onboarding system"""
    
    def __init__(self):
        self.quick_start = QuickStartManager()
        self.tutorials = TutorialSystem()
        self.scenarios = DemoScenarios()
    
    def cmd_start_onboarding(self, args):
        """Start a new onboarding session"""
        print("🚀 Welcome to AI Security Analyst in Your Pocket!")
        print("=" * 60)
        print()
        print("Let's get you started with a 5-minute security analysis.")
        print("You can either upload your own data or use our sample data.")
        print()
        
        user_id = args.user_id or input("Enter your user ID (or press Enter for 'demo_user'): ").strip() or "demo_user"
        
        # Start onboarding session
        session = self.quick_start.start_onboarding_session(user_id)
        
        print(f"✅ Onboarding session started: {session.session_id}")
        print()
        
        # Ask about data source
        print("Choose your data source:")
        print("1. Upload your own security data file")
        print("2. Generate sample security data for demonstration")
        print()
        
        choice = input("Enter your choice (1 or 2): ").strip()
        
        if choice == "1":
            self._handle_file_upload(session)
        else:
            self._handle_sample_data_generation(session)
        
        # Perform quick analysis
        print("\n🔍 Performing quick security analysis...")
        analysis_result = self.quick_start.perform_quick_analysis(session)
        
        # Display results
        self._display_analysis_results(analysis_result)
        
        # Offer next steps
        self._offer_next_steps(session)
        
        return 0
    
    def _handle_file_upload(self, session):
        """Handle user file upload"""
        file_path = input("Enter the path to your security data file: ").strip()
        
        if not Path(file_path).exists():
            print(f"❌ File not found: {file_path}")
            print("Falling back to sample data generation...")
            self._handle_sample_data_generation(session)
            return
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                file_content = f.read()
            
            filename = Path(file_path).name
            uploaded_file = self.quick_start.upload_sample_data(session, file_content, filename)
            
            print(f"✅ File uploaded successfully!")
            print(f"   Format detected: {uploaded_file.detected_format.value}")
            print(f"   Confidence: {uploaded_file.confidence_score:.2f}")
            print(f"   File size: {uploaded_file.file_size_bytes:,} bytes")
            
        except Exception as e:
            print(f"❌ Error uploading file: {str(e)}")
            print("Falling back to sample data generation...")
            self._handle_sample_data_generation(session)
    
    def _handle_sample_data_generation(self, session):
        """Handle sample data generation"""
        print("\n🔧 Generating realistic sample security data...")
        
        # Choose format
        print("Choose sample data format:")
        print("1. JSON (recommended)")
        print("2. CSV")
        print("3. CloudTrail logs")
        print("4. Syslog format")
        print()
        
        format_choice = input("Enter your choice (1-4, default: 1): ").strip() or "1"
        
        format_map = {
            "1": DataFormat.JSON,
            "2": DataFormat.CSV,
            "3": DataFormat.CLOUDTRAIL,
            "4": DataFormat.SYSLOG
        }
        
        data_format = format_map.get(format_choice, DataFormat.JSON)
        
        uploaded_file = self.quick_start.generate_sample_data_for_demo(
            session, 
            data_format=data_format,
            record_count=500
        )
        
        print(f"✅ Sample data generated successfully!")
        print(f"   Format: {uploaded_file.detected_format.value}")
        print(f"   Records: 500 (including suspicious activities)")
        print(f"   File size: {uploaded_file.file_size_bytes:,} bytes")
    
    def _display_analysis_results(self, analysis_result):
        """Display the analysis results in a user-friendly format"""
        print("\n" + "=" * 60)
        print("🎯 SECURITY ANALYSIS RESULTS")
        print("=" * 60)
        print()
        
        print(f"📊 Overall Security Score: {analysis_result.security_score}/100")
        print(f"⏱️  Analysis Duration: {analysis_result.analysis_duration_seconds:.1f} seconds")
        print(f"📁 Files Analyzed: {', '.join(analysis_result.files_analyzed)}")
        print()
        
        # Key findings
        print("🔍 KEY FINDINGS:")
        for i, finding in enumerate(analysis_result.key_findings, 1):
            print(f"   {i}. {finding}")
        print()
        
        # Critical issues
        if analysis_result.critical_issues:
            print("🚨 CRITICAL ISSUES REQUIRING IMMEDIATE ATTENTION:")
            for issue in analysis_result.critical_issues:
                print(f"   • {issue.get('title', 'Unknown Issue')}")
                print(f"     Severity: {issue.get('severity', 'Unknown')}")
                print(f"     Description: {issue.get('description', 'No description')}")
                if 'recommendation' in issue:
                    print(f"     Action: {issue['recommendation']}")
                print()
        
        # Recommendations
        print("💡 IMMEDIATE RECOMMENDATIONS:")
        for i, rec in enumerate(analysis_result.recommendations, 1):
            print(f"   {i}. {rec}")
        print()
        
        # Next steps
        print("📋 NEXT STEPS:")
        for i, step in enumerate(analysis_result.next_steps, 1):
            print(f"   {i}. {step}")
        print()
    
    def _offer_next_steps(self, session):
        """Offer next steps to the user"""
        print("🎓 CONTINUE YOUR LEARNING JOURNEY:")
        print()
        print("1. Take interactive tutorials")
        print("2. Try demonstration scenarios")
        print("3. Ask your own security questions")
        print("4. Complete onboarding")
        print()
        
        choice = input("What would you like to do next? (1-4): ").strip()
        
        if choice == "1":
            self._show_tutorials(session)
        elif choice == "2":
            self._show_scenarios(session)
        elif choice == "3":
            self._interactive_questions(session)
        else:
            self._complete_onboarding(session)
    
    def _show_tutorials(self, session):
        """Show available tutorials"""
        print("\n📚 AVAILABLE TUTORIALS:")
        print()
        
        tutorials = self.tutorials.get_available_tutorials()
        for i, tutorial in enumerate(tutorials, 1):
            print(f"{i}. {tutorial.title}")
            print(f"   Duration: {tutorial.estimated_duration_minutes} minutes")
            print(f"   Level: {tutorial.difficulty_level}")
            print(f"   Description: {tutorial.description}")
            print()
        
        choice = input(f"Choose a tutorial (1-{len(tutorials)}): ").strip()
        
        try:
            tutorial_index = int(choice) - 1
            if 0 <= tutorial_index < len(tutorials):
                selected_tutorial = tutorials[tutorial_index]
                self._run_tutorial(selected_tutorial, session)
            else:
                print("Invalid choice.")
        except ValueError:
            print("Invalid choice.")
    
    def _run_tutorial(self, tutorial, session):
        """Run an interactive tutorial"""
        print(f"\n🎓 Starting Tutorial: {tutorial.title}")
        print("=" * 60)
        print(tutorial.description)
        print()
        
        started_tutorial = self.tutorials.start_tutorial(tutorial.tutorial_id, session)
        
        for step in started_tutorial.steps:
            print(f"📖 Step: {step.title}")
            print(f"Description: {step.description}")
            print(f"Example Question: '{step.example_question}'")
            print(f"Expected Outcome: {step.expected_outcome}")
            print()
            
            if step.hints:
                print("💡 Hints:")
                for hint in step.hints:
                    print(f"   • {hint}")
                print()
            
            input("Press Enter when you've tried this step...")
            
            # Mark step as completed
            self.tutorials.complete_tutorial_step(
                tutorial.tutorial_id, 
                step.step_id, 
                session
            )
            
            print("✅ Step completed!")
            print()
        
        print(f"🎉 Tutorial '{tutorial.title}' completed!")
        
        # Generate certificate
        certificate = self.tutorials.generate_tutorial_certificate(tutorial.tutorial_id, session)
        print(f"🏆 Certificate earned: {certificate['certificate_id']}")
        print()
    
    def _show_scenarios(self, session):
        """Show available demonstration scenarios"""
        print("\n🎬 DEMONSTRATION SCENARIOS:")
        print()
        
        scenarios = self.scenarios.get_available_scenarios()
        for i, scenario in enumerate(scenarios, 1):
            print(f"{i}. {scenario.title}")
            print(f"   Duration: {scenario.estimated_duration_minutes} minutes")
            print(f"   Type: {scenario.scenario_type}")
            print(f"   Description: {scenario.description}")
            print(f"   Business Value: {scenario.business_value}")
            print()
        
        choice = input(f"Choose a scenario (1-{len(scenarios)}): ").strip()
        
        try:
            scenario_index = int(choice) - 1
            if 0 <= scenario_index < len(scenarios):
                selected_scenario = scenarios[scenario_index]
                self._run_scenario(selected_scenario, session)
            else:
                print("Invalid choice.")
        except ValueError:
            print("Invalid choice.")
    
    def _run_scenario(self, scenario, session):
        """Run a demonstration scenario"""
        print(f"\n🎬 Starting Scenario: {scenario.title}")
        print("=" * 60)
        print(scenario.description)
        print()
        print(f"Business Value: {scenario.business_value}")
        print()
        
        scenario_context = self.scenarios.start_scenario(scenario.scenario_id, session)
        
        for i, question in enumerate(scenario.key_questions):
            print(f"📝 Step {i+1}: Try asking this question:")
            print(f"   '{question}'")
            print()
            
            user_question = input("Enter your question (or press Enter to use the suggested one): ").strip()
            if not user_question:
                user_question = question
            
            # Complete the scenario step
            step_result = self.scenarios.complete_scenario_step(scenario_context, i, user_question)
            
            print(f"🤖 AI Response: {step_result['ai_response']}")
            print()
            
            if not step_result["is_complete"]:
                input("Press Enter to continue to the next step...")
                print()
        
        # Show completion summary
        if "completion_summary" in step_result:
            summary = step_result["completion_summary"]
            print("🎉 SCENARIO COMPLETED!")
            print("=" * 40)
            print(f"Scenario: {summary['scenario_completed']}")
            print(f"Value Demonstrated: {summary['business_value_demonstrated']}")
            print()
            print("Key Capabilities Shown:")
            for capability in summary['key_capabilities_shown']:
                print(f"   ✅ {capability}")
            print()
    
    def _interactive_questions(self, session):
        """Allow user to ask interactive questions"""
        print("\n💬 ASK YOUR OWN SECURITY QUESTIONS:")
        print("=" * 50)
        print("Now you can ask any security question in natural language.")
        print("Examples:")
        print("   • 'Are we being attacked right now?'")
        print("   • 'Show me failed login attempts from yesterday'")
        print("   • 'What's our compliance status?'")
        print("   • 'Find unusual user behavior'")
        print()
        print("Type 'quit' to exit.")
        print()
        
        while True:
            question = input("🔍 Your question: ").strip()
            
            if question.lower() in ['quit', 'exit', 'q']:
                break
            
            if not question:
                continue
            
            # Simulate AI response (in real implementation, this would call the full pipeline)
            print("🤖 AI Security Analyst is analyzing...")
            print("   (In the full system, this would query your data and provide real insights)")
            print("   For now, this demonstrates the natural language interface.")
            print()
    
    def _complete_onboarding(self, session):
        """Complete the onboarding process"""
        summary = self.quick_start.complete_onboarding(session)
        
        print("\n🎉 ONBOARDING COMPLETED!")
        print("=" * 50)
        print()
        print("Congratulations! You've successfully completed the AI Security Analyst onboarding.")
        print()
        print("📊 Your Achievements:")
        for achievement in summary['key_achievements']:
            print(f"   ✅ {achievement}")
        print()
        print("🚀 Next Actions:")
        for action in summary['next_actions']:
            print(f"   • {action}")
        print()
        print("Thank you for trying AI Security Analyst in Your Pocket!")
        print("Visit our documentation for advanced features and integrations.")
    
    def cmd_list_tutorials(self, args):
        """List available tutorials"""
        tutorials = self.tutorials.get_available_tutorials(args.difficulty)
        
        print("📚 Available Tutorials:")
        print()
        
        for tutorial in tutorials:
            print(f"ID: {tutorial.tutorial_id}")
            print(f"Title: {tutorial.title}")
            print(f"Duration: {tutorial.estimated_duration_minutes} minutes")
            print(f"Level: {tutorial.difficulty_level}")
            print(f"Description: {tutorial.description}")
            print()
        
        return 0
    
    def cmd_list_scenarios(self, args):
        """List available demonstration scenarios"""
        scenarios = self.scenarios.get_available_scenarios(args.type)
        
        print("🎬 Available Demonstration Scenarios:")
        print()
        
        for scenario in scenarios:
            print(f"ID: {scenario.scenario_id}")
            print(f"Title: {scenario.title}")
            print(f"Type: {scenario.scenario_type}")
            print(f"Duration: {scenario.estimated_duration_minutes} minutes")
            print(f"Description: {scenario.description}")
            print(f"Business Value: {scenario.business_value}")
            print()
        
        return 0
    
    def cmd_generate_sample_data(self, args):
        """Generate sample security data"""
        format_map = {
            'json': DataFormat.JSON,
            'csv': DataFormat.CSV,
            'cloudtrail': DataFormat.CLOUDTRAIL,
            'syslog': DataFormat.SYSLOG,
            'vpc_flow': DataFormat.VPC_FLOW
        }
        
        data_format = format_map.get(args.format.lower(), DataFormat.JSON)
        
        print(f"🔧 Generating {args.count} sample records in {data_format.value} format...")
        
        generator = self.quick_start.sample_generator
        sample_data = generator.generate_sample_dataset(
            format_type=data_format,
            record_count=args.count,
            include_threats=args.include_threats
        )
        
        if args.output:
            with open(args.output, 'w') as f:
                f.write(sample_data)
            print(f"✅ Sample data written to: {args.output}")
        else:
            print("Sample data (first 10 lines):")
            print("-" * 40)
            lines = sample_data.split('\n')[:10]
            for line in lines:
                print(line)
            if len(sample_data.split('\n')) > 10:
                print("... (truncated)")
        
        return 0


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='AI Security Analyst Onboarding System',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Global arguments
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Start onboarding command
    start_parser = subparsers.add_parser('start', help='Start onboarding process')
    start_parser.add_argument('--user-id', help='User ID for the session')
    start_parser.set_defaults(func=OnboardingCLI().cmd_start_onboarding)
    
    # List tutorials command
    tutorials_parser = subparsers.add_parser('tutorials', help='List available tutorials')
    tutorials_parser.add_argument('--difficulty', choices=['beginner', 'intermediate', 'advanced'],
                                help='Filter by difficulty level')
    tutorials_parser.set_defaults(func=OnboardingCLI().cmd_list_tutorials)
    
    # List scenarios command
    scenarios_parser = subparsers.add_parser('scenarios', help='List available scenarios')
    scenarios_parser.add_argument('--type', help='Filter by scenario type')
    scenarios_parser.set_defaults(func=OnboardingCLI().cmd_list_scenarios)
    
    # Generate sample data command
    sample_parser = subparsers.add_parser('generate-sample', help='Generate sample security data')
    sample_parser.add_argument('--format', default='json',
                             choices=['json', 'csv', 'cloudtrail', 'syslog', 'vpc_flow'],
                             help='Data format to generate')
    sample_parser.add_argument('--count', type=int, default=100,
                             help='Number of records to generate')
    sample_parser.add_argument('--include-threats', action='store_true',
                             help='Include suspicious activities in the data')
    sample_parser.add_argument('--output', help='Output file path')
    sample_parser.set_defaults(func=OnboardingCLI().cmd_generate_sample_data)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # Execute command
    if hasattr(args, 'func'):
        try:
            return args.func(args)
        except KeyboardInterrupt:
            print("\n⚠️ Operation cancelled by user")
            return 1
        except Exception as e:
            logger.error(f"❌ Command failed: {str(e)}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            return 1
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())