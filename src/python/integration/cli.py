"""
Unified Analysis Platform CLI

Command-line interface for the unified analysis platform.
Provides easy access to all analysis capabilities through a single CLI.
"""

import asyncio
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import List, Optional

from .unified_analysis_platform import UnifiedAnalysisPlatform, UnifiedAnalysisRequest
from .analysis_dashboard import AnalysisDashboard
from .workflow_orchestrator import WorkflowOrchestrator


def setup_logging(verbose: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )


async def run_simple_analysis(args):
    """Run simple unified analysis"""
    print(f"🔍 Starting unified analysis of: {args.target}")
    
    platform = UnifiedAnalysisPlatform()
    
    try:
        request = UnifiedAnalysisRequest(
            analysis_id=f"cli_{args.target.replace('/', '_').replace('\\', '_')}",
            target_path=args.target,
            analysis_types=args.types,
            include_recommendations=not args.no_recommendations,
            include_cross_component_correlation=not args.no_correlation
        )
        
        print(f"📊 Analysis types: {', '.join(args.types)}")
        print("⏳ Running analysis...")
        
        report = await platform.run_unified_analysis(request)
        
        print(f"✅ Analysis completed!")
        print(f"🎯 Security Score: {report.overall_security_score:.1%}")
        print(f"🔧 Components: {len(report.component_results)}")
        print(f"💡 Insights: {len(report.cross_component_insights)}")
        print(f"📝 Recommendations: {len(report.unified_recommendations)}")
        
        # Generate report if requested
        if args.generate_report:
            dashboard = AnalysisDashboard()
            report_path = dashboard.generate_unified_report(report)
            print(f"📄 Report generated: {report_path}")
            
            if args.open_report:
                dashboard.open_report_in_browser(report_path)
        
        # Save JSON if requested
        if args.output_json:
            output_path = Path(args.output_json)
            with open(output_path, 'w') as f:
                json.dump(report.__dict__, f, indent=2, default=str)
            print(f"💾 JSON report saved: {output_path}")
        
        # Print summary
        print("\n" + "="*60)
        print("ANALYSIS SUMMARY")
        print("="*60)
        print(report.analysis_summary)
        
        if report.unified_recommendations:
            print("\n🔧 TOP RECOMMENDATIONS:")
            for i, rec in enumerate(report.unified_recommendations[:5], 1):
                print(f"  {i}. {rec}")
    
    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        return 1
    
    finally:
        platform.close()
    
    return 0


async def run_workflow_analysis(args):
    """Run workflow-based analysis"""
    print(f"🔄 Starting workflow analysis of: {args.target}")
    
    orchestrator = WorkflowOrchestrator()
    
    try:
        # Create workflow based on type
        if args.workflow_type == "comprehensive":
            workflow = orchestrator.create_comprehensive_analysis_workflow(
                args.target, args.workflow_name
            )
        elif args.workflow_type == "security":
            workflow = orchestrator.create_security_focused_workflow(
                args.target, args.workflow_name
            )
        elif args.workflow_type == "compliance":
            workflow = orchestrator.create_compliance_workflow(
                args.target, args.workflow_name
            )
        elif args.workflow_type == "documentation":
            workflow = orchestrator.create_documentation_workflow(
                args.target, args.workflow_name
            )
        else:
            print(f"❌ Unknown workflow type: {args.workflow_type}")
            return 1
        
        print(f"📋 Workflow: {workflow.workflow_name}")
        print(f"🔧 Tasks: {len(workflow.tasks)}")
        print(f"⏱️  Estimated duration: {workflow.metadata.get('estimated_duration_minutes', 'unknown')} minutes")
        
        print("⏳ Executing workflow...")
        
        result = await orchestrator.execute_workflow(workflow)
        
        if result.status.value == "completed":
            print("✅ Workflow completed successfully!")
            
            if result.unified_report:
                print(f"🎯 Security Score: {result.unified_report.overall_security_score:.1%}")
                print(f"💡 Insights: {len(result.unified_report.cross_component_insights)}")
                print(f"📝 Recommendations: {len(result.unified_report.unified_recommendations)}")
                
                # Generate report if requested
                if args.generate_report:
                    dashboard = AnalysisDashboard()
                    report_path = dashboard.generate_unified_report(result.unified_report)
                    print(f"📄 Report generated: {report_path}")
                    
                    if args.open_report:
                        dashboard.open_report_in_browser(report_path)
        else:
            print(f"❌ Workflow failed with status: {result.status.value}")
            if result.error_message:
                print(f"Error: {result.error_message}")
            return 1
        
        # Print execution summary
        print("\n" + "="*60)
        print("WORKFLOW SUMMARY")
        print("="*60)
        summary = result.execution_summary
        print(f"Status: {summary['status']}")
        print(f"Tasks: {summary['successful_tasks']}/{summary['total_tasks']} successful")
        print(f"Execution Time: {summary['execution_time_seconds']:.1f} seconds")
        print(f"Components: {', '.join(summary['components_used'])}")
    
    except Exception as e:
        print(f"❌ Workflow execution failed: {e}")
        return 1
    
    finally:
        orchestrator.close()
    
    return 0


def list_workflow_status(args):
    """List workflow status"""
    orchestrator = WorkflowOrchestrator()
    
    try:
        if args.workflow_id:
            # Get specific workflow status
            status = orchestrator.get_workflow_status(args.workflow_id)
            if status:
                print(f"Workflow: {args.workflow_id}")
                print(f"Status: {status['status']}")
                print(f"Progress: {status.get('progress', 0):.1f}%")
                
                if 'current_tasks' in status:
                    print("Tasks:")
                    for task in status['current_tasks']:
                        print(f"  - {task['task_id']}: {task['status']} ({task['component']})")
            else:
                print(f"❌ Workflow not found: {args.workflow_id}")
                return 1
        else:
            # List active workflows
            active = orchestrator.list_active_workflows()
            if active:
                print("Active Workflows:")
                for workflow in active:
                    print(f"  - {workflow['workflow_id']}: {workflow['status']} ({workflow['progress']:.1f}%)")
            else:
                print("No active workflows")
            
            # List recent history
            history = orchestrator.get_workflow_history(5)
            if history:
                print("\nRecent Workflows:")
                for workflow in history:
                    print(f"  - {workflow['workflow_id']}: {workflow['status']}")
    
    except Exception as e:
        print(f"❌ Failed to get workflow status: {e}")
        return 1
    
    finally:
        orchestrator.close()
    
    return 0


def create_sample_report(args):
    """Create sample dashboard report"""
    try:
        from .analysis_dashboard import create_sample_dashboard_report
        
        print("📊 Creating sample dashboard report...")
        report_path = create_sample_dashboard_report()
        print(f"✅ Sample report created: {report_path}")
        
        if args.open_report:
            dashboard = AnalysisDashboard()
            dashboard.open_report_in_browser(report_path)
    
    except Exception as e:
        print(f"❌ Failed to create sample report: {e}")
        return 1
    
    return 0


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Unified Analysis Platform CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Simple security analysis
  python -m integration.cli analyze ./src --types security sast
  
  # Documentation analysis
  python -m integration.cli analyze ./src --types documentation governance_validation deployment_readiness
  
  # Comprehensive workflow analysis with report
  python -m integration.cli workflow ./src --type comprehensive --report --open
  
  # Documentation-focused analysis
  python -m integration.cli workflow ./src --type documentation --name "Documentation Review"
  
  # Compliance-focused analysis
  python -m integration.cli workflow ./src --type compliance --name "Compliance Check"
  
  # List active workflows
  python -m integration.cli status
  
  # Create sample report
  python -m integration.cli sample --open
        """
    )
    
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Run simple unified analysis')
    analyze_parser.add_argument('target', help='Target path to analyze')
    analyze_parser.add_argument('--types', nargs='+', 
                               choices=['security', 'compliance', 'sast', 'secrets', 'crypto', 'performance', 'governance', 'documentation', 'governance_validation', 'deployment_readiness'],
                               default=['security', 'compliance'],
                               help='Analysis types to run')
    analyze_parser.add_argument('--no-recommendations', action='store_true',
                               help='Skip recommendation generation')
    analyze_parser.add_argument('--no-correlation', action='store_true',
                               help='Skip cross-component correlation')
    analyze_parser.add_argument('--generate-report', '--report', action='store_true',
                               help='Generate HTML report')
    analyze_parser.add_argument('--open-report', '--open', action='store_true',
                               help='Open report in browser')
    analyze_parser.add_argument('--output-json', '-o', 
                               help='Save JSON report to file')
    
    # Workflow command
    workflow_parser = subparsers.add_parser('workflow', help='Run workflow-based analysis')
    workflow_parser.add_argument('target', help='Target path to analyze')
    workflow_parser.add_argument('--type', dest='workflow_type',
                                choices=['comprehensive', 'security', 'compliance', 'documentation'],
                                default='comprehensive',
                                help='Workflow type')
    workflow_parser.add_argument('--name', dest='workflow_name',
                                help='Custom workflow name')
    workflow_parser.add_argument('--generate-report', '--report', action='store_true',
                                help='Generate HTML report')
    workflow_parser.add_argument('--open-report', '--open', action='store_true',
                                help='Open report in browser')
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Check workflow status')
    status_parser.add_argument('workflow_id', nargs='?',
                              help='Specific workflow ID to check')
    
    # Sample command
    sample_parser = subparsers.add_parser('sample', help='Create sample dashboard report')
    sample_parser.add_argument('--open-report', '--open', action='store_true',
                              help='Open report in browser')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    # Handle commands
    if args.command == 'analyze':
        return asyncio.run(run_simple_analysis(args))
    elif args.command == 'workflow':
        return asyncio.run(run_workflow_analysis(args))
    elif args.command == 'status':
        return list_workflow_status(args)
    elif args.command == 'sample':
        return create_sample_report(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())