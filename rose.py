#!/usr/bin/env python3
"""
ROSe - Read-Only Security Analyst
AI-Powered Security Intelligence Platform

Usage:
    # Interactive AI Security Analyst (talk to your security data!)
    python rose.py chat
    python rose.py analyst
    
    # Quick security analysis
    python rose.py analyze /path/to/project
    python rose.py analyze . --types security sast secrets
    
    # Comprehensive workflows
    python rose.py workflow . --type security
    
    # Demo features
    python rose.py demo web          # Web dashboard
    python rose.py demo cost         # Cost optimization
    python rose.py demo insights     # Security insights
    python rose.py demo onboarding   # Interactive tutorial
    
    # AWS features (requires AWS setup)
    python rose.py aws deploy        # Deploy AWS infrastructure
    python rose.py aws validate      # Validate AWS setup
    
    # Help
    python rose.py --help
    python rose.py help
"""

import sys
import os
from pathlib import Path

# Add src/python to path
src_path = Path(__file__).parent / "src" / "python"
sys.path.insert(0, str(src_path))

def show_help():
    """Display help information"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║         ROSe - Read-Only Security AI Analyst                ║
║              AI-Powered Security Intelligence                ║
╚══════════════════════════════════════════════════════════════╝

🤖 INTERACTIVE AI SECURITY ANALYST (Main Feature):
   python rose.py chat              Talk to your AI security analyst
   python rose.py analyst           Same as 'chat'
   python rose.py ai                Same as 'chat'

📊 SECURITY ANALYSIS:
   python rose.py analyze .         Analyze current directory
   python rose.py analyze PATH      Analyze specific path
   python rose.py analyze . --types security sast secrets
   python rose.py workflow . --type comprehensive

🎬 DEMO FEATURES:
   python rose.py demo web          Web dashboard (localhost:8000)
   python rose.py demo cost         Cost optimization analysis
   python rose.py demo insights     Security insights generator
   python rose.py demo onboarding   Interactive tutorial
   python rose.py demo pipeline     Integration pipeline demo

☁️  AWS FEATURES (requires AWS setup):
   python rose.py aws deploy        Deploy AWS infrastructure
   python rose.py aws validate      Validate AWS configuration

📖 HELP:
   python rose.py help              Show this help
   python rose.py --help            Show this help

💡 QUICK START:
   1. pip install -e .
   2. python rose.py chat
   3. Ask: "What are our top security risks?"

🔗 More info: See ROSE_COMMANDS.md for full command reference
""")

def main():
    """Main entry point for ROSe CLI"""
    
    # Check for help first
    if len(sys.argv) > 1 and sys.argv[1].lower() in ['help', '--help', '-h', '/?']:
        show_help()
        return 0
    
    # Check for special commands
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        # AI Security Analyst Chat Interface
        if command in ['chat', 'analyst', 'ai', 'ask']:
            print("🤖 Starting ROSe AI Security Analyst...")
            print("Ask me anything about your security posture!\n")
            try:
                from aws_bedrock_athena_ai.cli import main as analyst_main
                return analyst_main()
            except ImportError as e:
                print(f"❌ Error loading AI analyst module: {e}")
                print("💡 Make sure you've installed dependencies:")
                print("   pip install -r requirements.txt")
                print("   pip install -e .")
                return 1
            except Exception as e:
                print(f"❌ Unexpected error starting chat interface: {e}")
                print("💡 Try running: python rose.py demo web")
                print("   Or check logs for more details")
                return 1
        
        # Demo commands
        elif command == 'demo':
            if len(sys.argv) > 2:
                demo_type = sys.argv[2].lower()
                
                if demo_type == 'web':
                    print("🌐 Starting Web Dashboard...")
                    try:
                        from aws_bedrock_athena_ai.demo_web_interface import main as web_main
                        return web_main()
                    except ImportError as e:
                        print(f"❌ Error: {e}")
                        return 1
                
                elif demo_type == 'cost':
                    print("💰 Running Cost Optimization Demo...")
                    try:
                        from aws_bedrock_athena_ai.demo_cost_optimization import main as cost_main
                        return cost_main()
                    except ImportError as e:
                        print(f"❌ Error: {e}")
                        return 1
                
                elif demo_type == 'insights':
                    print("📊 Generating Security Insights...")
                    try:
                        from aws_bedrock_athena_ai.demo_insights_simple import main as insights_main
                        return insights_main()
                    except ImportError as e:
                        print(f"❌ Error: {e}")
                        return 1
                
                elif demo_type == 'onboarding':
                    print("🎓 Starting Interactive Tutorial...")
                    try:
                        from aws_bedrock_athena_ai.demo_onboarding_simple import main as onboard_main
                        return onboard_main()
                    except ImportError as e:
                        print(f"❌ Error: {e}")
                        return 1
                
                elif demo_type == 'pipeline':
                    print("🔄 Running Integration Pipeline Demo...")
                    try:
                        from aws_bedrock_athena_ai.demo_integration_pipeline import main as pipeline_main
                        return pipeline_main()
                    except ImportError as e:
                        print(f"❌ Error: {e}")
                        return 1
                
                else:
                    print(f"❌ Unknown demo type: {demo_type}")
                    print("\nAvailable demos:")
                    print("  web, cost, insights, onboarding, pipeline")
                    print("\nExample: python rose.py demo web")
                    return 1
            else:
                print("Available demos:")
                print("  python rose.py demo web          - Web dashboard")
                print("  python rose.py demo cost         - Cost optimization")
                print("  python rose.py demo insights     - Security insights")
                print("  python rose.py demo onboarding   - Interactive tutorial")
                print("  python rose.py demo pipeline     - Integration pipeline")
                return 0
        
        # AWS commands
        elif command == 'aws':
            if len(sys.argv) > 2:
                aws_command = sys.argv[2].lower()
                
                if aws_command == 'deploy':
                    print("☁️  Deploying AWS Infrastructure...")
                    try:
                        from aws_bedrock_athena_ai.infrastructure.deploy_infrastructure import main as deploy_main
                        return deploy_main()
                    except ImportError as e:
                        print(f"❌ Error: {e}")
                        return 1
                
                elif aws_command == 'validate':
                    print("✅ Validating AWS Setup...")
                    import subprocess
                    result = subprocess.run([sys.executable, "scripts/validate-aws-setup.py"])
                    return result.returncode
                
                else:
                    print(f"❌ Unknown AWS command: {aws_command}")
                    print("\nAvailable AWS commands:")
                    print("  deploy, validate")
                    print("\nExample: python rose.py aws deploy")
                    return 1
            else:
                print("Available AWS commands:")
                print("  python rose.py aws deploy    - Deploy AWS infrastructure")
                print("  python rose.py aws validate  - Validate AWS setup")
                return 0
    
    # Default to integration CLI for analyze/workflow commands
    try:
        from integration.cli import main as integration_main
        return integration_main()
    except ImportError as e:
        print(f"❌ Error loading integration CLI: {e}")
        print("💡 Make sure you've installed dependencies: pip install -r requirements.txt")
        return 1

if __name__ == "__main__":
    sys.exit(main())
