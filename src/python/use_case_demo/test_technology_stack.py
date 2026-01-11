"""
Simple test for Technology Stack Analyzer
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.append(str(project_root))

from technology_stack_analyzer import TechnologyStackAnalyzer

def test_technology_stack_analyzer():
    """Test basic functionality of the technology stack analyzer."""
    print("Testing Technology Stack Analyzer...")
    
    # Initialize analyzer
    analyzer = TechnologyStackAnalyzer()
    
    # Test analysis
    analysis = analyzer.analyze_technology_stack()
    
    # Validate results
    assert 'timestamp' in analysis
    assert 'component_analyses' in analysis
    assert 'compliance_results' in analysis
    assert 'cost_analysis' in analysis
    assert 'deployment_readiness' in analysis
    assert 'recommendations' in analysis
    assert 'overall_score' in analysis
    
    print(f"✓ Analysis completed successfully")
    print(f"✓ Overall Score: {analysis['overall_score']}/100")
    print(f"✓ Components analyzed: {len(analysis['component_analyses'])}")
    print(f"✓ Recommendations generated: {len(analysis['recommendations'])}")
    
    # Test report generation
    report = analyzer.generate_compliance_report()
    assert len(report) > 0
    assert "Technology Stack Compliance Report" in report
    
    print(f"✓ Compliance report generated ({len(report)} characters)")
    
    print("All tests passed!")
    return True

if __name__ == "__main__":
    test_technology_stack_analyzer()