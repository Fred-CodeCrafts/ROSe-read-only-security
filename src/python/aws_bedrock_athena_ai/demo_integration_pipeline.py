#!/usr/bin/env python3
"""
Demo script for the AI Security Analyst Pipeline integration.

This script demonstrates the complete NLI → Athena → Bedrock → Insights pipeline
with error handling and graceful degradation.
"""

import sys
import os
import logging
from datetime import datetime

# Add the current directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from integration.ai_security_analyst_pipeline import AISecurityAnalystPipeline
from insights.models import AudienceType

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def demo_successful_pipeline():
    """Demonstrate successful pipeline execution."""
    print("\n" + "="*60)
    print("🚀 AI SECURITY ANALYST PIPELINE DEMO")
    print("="*60)
    
    try:
        # Initialize pipeline
        print("\n1. Initializing AI Security Analyst Pipeline...")
        pipeline = AISecurityAnalystPipeline(aws_region="us-east-1")
        
        # Check pipeline status
        print("\n2. Checking pipeline status...")
        status = pipeline.get_pipeline_status()
        print(f"   Pipeline Health: {'✅ Healthy' if status['pipeline_healthy'] else '❌ Unhealthy'}")
        
        # Get example questions
        print("\n3. Available example questions:")
        examples = pipeline.get_example_questions()
        for i, example in enumerate(examples[:5], 1):
            print(f"   {i}. {example}")
        
        # Process a security question
        print("\n4. Processing security question...")
        question = "Are we being attacked right now?"
        print(f"   Question: {question}")
        
        result = pipeline.process_security_question(
            question=question,
            user_id="demo_user",
            target_audiences=[AudienceType.EXECUTIVE, AudienceType.TECHNICAL],
            max_cost_usd=0.10
        )
        
        # Display results
        print(f"\n5. Pipeline Results:")
        print(f"   Success: {'✅ Yes' if result.success else '❌ No'}")
        print(f"   Session ID: {result.session_id}")
        print(f"   Processing Time: {result.processing_time_ms:.1f}ms")
        print(f"   Cost: ${result.cost_usd:.4f}")
        
        if result.error_message:
            print(f"   Error: {result.error_message}")
        
        if result.warnings:
            print(f"   Warnings: {len(result.warnings)}")
            for warning in result.warnings:
                print(f"     - {warning}")
        
        # Show NLP response
        if result.nlp_response:
            print(f"\n6. Natural Language Processing:")
            print(f"   Intent: {result.nlp_response.intent.intent_type.value}")
            print(f"   Confidence: {result.nlp_response.intent.confidence:.2f}")
            print(f"   Needs Clarification: {result.nlp_response.needs_clarification}")
        
        # Show threat analysis
        if result.threat_analysis:
            print(f"\n7. Threat Analysis:")
            print(f"   Threats Found: {len(result.threat_analysis.threats_identified)}")
            print(f"   Risk Score: {result.threat_analysis.risk_assessment.overall_risk_score}/10")
            print(f"   Confidence: {result.threat_analysis.confidence_level:.2f}")
            print(f"   Summary: {result.threat_analysis.summary}")
        
        # Show insights
        if result.insights_package:
            print(f"\n8. Generated Insights:")
            print(f"   Analysis ID: {result.insights_package.get('analysis_id', 'N/A')}")
            audiences = result.insights_package.get('audiences', {})
            print(f"   Audiences: {', '.join(audiences.keys())}")
            
            summary = result.insights_package.get('summary', {})
            if summary:
                print(f"   Total Threats: {summary.get('total_threats', 0)}")
                print(f"   Critical Issues: {summary.get('critical_issues', 0)}")
                print(f"   Recommendations: {summary.get('recommendations_count', 0)}")
        
        print(f"\n✅ Pipeline demo completed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Pipeline demo failed: {str(e)}")
        logger.error(f"Demo failed: {str(e)}", exc_info=True)
        return False


def demo_clarification_handling():
    """Demonstrate clarification handling."""
    print("\n" + "="*60)
    print("🤔 CLARIFICATION HANDLING DEMO")
    print("="*60)
    
    try:
        pipeline = AISecurityAnalystPipeline(aws_region="us-east-1")
        
        # Test with ambiguous question
        ambiguous_question = "Show me stuff"
        print(f"\n1. Processing ambiguous question: '{ambiguous_question}'")
        
        result = pipeline.process_security_question(
            question=ambiguous_question,
            user_id="demo_user",
            conversation_id="demo_conv_1"
        )
        
        print(f"   Success: {'✅ Yes' if result.success else '❌ No'}")
        
        if result.nlp_response and result.nlp_response.needs_clarification:
            print(f"   ✅ Clarification needed (as expected)")
            if hasattr(result.nlp_response.intent, 'clarification_questions'):
                for i, question in enumerate(result.nlp_response.intent.clarification_questions, 1):
                    print(f"     {i}. {question}")
        else:
            print(f"   ⚠️ No clarification requested")
        
        # Test clarification response
        print(f"\n2. Handling clarification response...")
        clarification_result = pipeline.handle_clarification_response(
            original_question=ambiguous_question,
            clarification_response="Show me security threats from last week",
            conversation_id="demo_conv_1",
            user_id="demo_user"
        )
        
        print(f"   Clarification Success: {'✅ Yes' if clarification_result.success else '❌ No'}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Clarification demo failed: {str(e)}")
        logger.error(f"Clarification demo failed: {str(e)}", exc_info=True)
        return False


def demo_error_handling():
    """Demonstrate error handling and graceful degradation."""
    print("\n" + "="*60)
    print("🛡️ ERROR HANDLING DEMO")
    print("="*60)
    
    try:
        pipeline = AISecurityAnalystPipeline(aws_region="us-east-1")
        
        # Test with cost limit exceeded
        print(f"\n1. Testing cost limit handling...")
        result = pipeline.process_security_question(
            question="Analyze all security data from the past year",
            user_id="demo_user",
            max_cost_usd=0.001  # Very low limit
        )
        
        print(f"   Success: {'✅ Yes' if result.success else '❌ No'}")
        if result.error_message:
            print(f"   Error (expected): {result.error_message}")
        if result.warnings:
            print(f"   Warnings: {len(result.warnings)}")
        
        # Test with valid question but potential service issues
        print(f"\n2. Testing graceful degradation...")
        result = pipeline.process_security_question(
            question="Are we being attacked?",
            user_id="demo_user",
            max_cost_usd=0.10
        )
        
        print(f"   Success: {'✅ Yes' if result.success else '❌ No'}")
        if result.warnings:
            print(f"   Warnings: {len(result.warnings)}")
            for warning in result.warnings:
                print(f"     - {warning}")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Error handling demo failed: {str(e)}")
        logger.error(f"Error handling demo failed: {str(e)}", exc_info=True)
        return False


def main():
    """Run all pipeline demos."""
    print("🎯 AI Security Analyst Pipeline Integration Demo")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    demos = [
        ("Successful Pipeline Execution", demo_successful_pipeline),
        ("Clarification Handling", demo_clarification_handling),
        ("Error Handling & Graceful Degradation", demo_error_handling)
    ]
    
    results = []
    
    for demo_name, demo_func in demos:
        print(f"\n{'='*20} {demo_name} {'='*20}")
        try:
            success = demo_func()
            results.append((demo_name, success))
        except Exception as e:
            print(f"❌ Demo '{demo_name}' crashed: {str(e)}")
            results.append((demo_name, False))
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 DEMO SUMMARY")
    print(f"{'='*60}")
    
    for demo_name, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"  {demo_name}: {status}")
    
    total_passed = sum(1 for _, success in results if success)
    print(f"\nOverall: {total_passed}/{len(results)} demos passed")
    
    if total_passed == len(results):
        print("🎉 All integration demos completed successfully!")
        return 0
    else:
        print("⚠️ Some demos failed - check logs for details")
        return 1


if __name__ == "__main__":
    sys.exit(main())