"""
Unified Analysis Reporting Dashboard

Provides comprehensive reporting and visualization capabilities for the unified analysis platform.
Creates unified reports that correlate insights across all analysis components.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import asdict
import tempfile
import webbrowser

from .unified_analysis_platform import (
    UnifiedAnalysisReport, ComponentAnalysisResult, CrossComponentInsight,
    UnifiedAnalysisRequest
)


class AnalysisDashboard:
    """
    Unified Analysis Dashboard
    
    Creates comprehensive reports and dashboards that present analysis results
    from all components in a unified, correlated view.
    """
    
    def __init__(self, output_dir: str = "data/analysis/reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
    
    def generate_unified_report(self, analysis_report: UnifiedAnalysisReport) -> str:
        """
        Generate comprehensive unified analysis report
        
        Args:
            analysis_report: Unified analysis results from all components
            
        Returns:
            Path to generated HTML report
        """
        self.logger.info(f"Generating unified report for analysis {analysis_report.analysis_id}")
        
        # Generate HTML report
        html_content = self._generate_html_report(analysis_report)
        
        # Save report
        report_filename = f"unified_analysis_{analysis_report.analysis_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        report_path = self.output_dir / report_filename
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Generate JSON report for programmatic access
        json_filename = f"unified_analysis_{analysis_report.analysis_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        json_path = self.output_dir / json_filename
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(asdict(analysis_report), f, indent=2, default=str)
        
        self.logger.info(f"Unified report generated: {report_path}")
        return str(report_path)
    
    def generate_executive_summary(self, analysis_report: UnifiedAnalysisReport) -> str:
        """
        Generate executive summary report
        
        Args:
            analysis_report: Unified analysis results
            
        Returns:
            Path to generated executive summary
        """
        summary_content = self._generate_executive_summary_content(analysis_report)
        
        summary_filename = f"executive_summary_{analysis_report.analysis_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        summary_path = self.output_dir / summary_filename
        
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(summary_content)
        
        return str(summary_path)
    
    def generate_component_correlation_matrix(self, analysis_report: UnifiedAnalysisReport) -> str:
        """
        Generate component correlation analysis
        
        Args:
            analysis_report: Unified analysis results
            
        Returns:
            Path to correlation matrix report
        """
        correlation_content = self._generate_correlation_matrix(analysis_report)
        
        correlation_filename = f"correlation_matrix_{analysis_report.analysis_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        correlation_path = self.output_dir / correlation_filename
        
        with open(correlation_path, 'w', encoding='utf-8') as f:
            f.write(correlation_content)
        
        return str(correlation_path)
    
    def open_report_in_browser(self, report_path: str):
        """Open generated report in default browser"""
        try:
            webbrowser.open(f"file://{Path(report_path).absolute()}")
            self.logger.info(f"Opened report in browser: {report_path}")
        except Exception as e:
            self.logger.error(f"Failed to open report in browser: {e}")
    
    def _generate_html_report(self, analysis_report: UnifiedAnalysisReport) -> str:
        """Generate comprehensive HTML report"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unified Security Analysis Report - {analysis_id}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #2c3e50;
            margin: 0;
            font-size: 2.5em;
        }}
        .header .subtitle {{
            color: #7f8c8d;
            font-size: 1.2em;
            margin-top: 10px;
        }}
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .card h3 {{
            margin: 0 0 10px 0;
            font-size: 1.1em;
        }}
        .card .value {{
            font-size: 2em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .security-score {{
            background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
        }}
        .security-score.medium {{
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
        }}
        .security-score.low {{
            background: linear-gradient(135deg, #fc4a1a 0%, #f7b733 100%);
        }}
        .section {{
            margin-bottom: 40px;
        }}
        .section h2 {{
            color: #2c3e50;
            border-left: 4px solid #3498db;
            padding-left: 15px;
            margin-bottom: 20px;
        }}
        .component-result {{
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .component-result h3 {{
            color: #495057;
            margin-top: 0;
        }}
        .status-success {{
            border-left: 4px solid #28a745;
        }}
        .status-error {{
            border-left: 4px solid #dc3545;
        }}
        .status-partial {{
            border-left: 4px solid #ffc107;
        }}
        .insight {{
            background-color: #e3f2fd;
            border: 1px solid #bbdefb;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}
        .insight h4 {{
            color: #1976d2;
            margin-top: 0;
        }}
        .recommendations {{
            background-color: #f1f8e9;
            border: 1px solid #c8e6c9;
            border-radius: 8px;
            padding: 20px;
        }}
        .recommendations ul {{
            margin: 0;
            padding-left: 20px;
        }}
        .recommendations li {{
            margin-bottom: 8px;
        }}
        .metadata {{
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            font-family: monospace;
            font-size: 0.9em;
        }}
        .confidence-bar {{
            width: 100%;
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .confidence-fill {{
            height: 100%;
            background: linear-gradient(90deg, #ff6b6b 0%, #feca57 50%, #48dbfb 100%);
            transition: width 0.3s ease;
        }}
        .execution-time {{
            color: #6c757d;
            font-size: 0.9em;
            font-style: italic;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            border: 1px solid #dee2e6;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: 600;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #6c757d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Unified Security Analysis Report</h1>
            <div class="subtitle">Analysis ID: {analysis_id}</div>
            <div class="subtitle">Target: {target_path}</div>
            <div class="subtitle">Generated: {timestamp}</div>
        </div>
        
        <div class="summary-cards">
            <div class="card security-score {security_score_class}">
                <h3>Overall Security Score</h3>
                <div class="value">{security_score}%</div>
            </div>
            <div class="card">
                <h3>Components Analyzed</h3>
                <div class="value">{components_count}</div>
            </div>
            <div class="card">
                <h3>Cross-Component Insights</h3>
                <div class="value">{insights_count}</div>
            </div>
            <div class="card">
                <h3>Total Execution Time</h3>
                <div class="value">{execution_time}s</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Analysis Summary</h2>
            <div class="metadata">
                {analysis_summary}
            </div>
        </div>
        
        <div class="section">
            <h2>Component Analysis Results</h2>
            {component_results_html}
        </div>
        
        <div class="section">
            <h2>Cross-Component Insights</h2>
            {insights_html}
        </div>
        
        <div class="section">
            <h2>Unified Recommendations</h2>
            <div class="recommendations">
                <ul>
                    {recommendations_html}
                </ul>
            </div>
        </div>
        
        <div class="section">
            <h2>Execution Metadata</h2>
            <div class="metadata">
                {metadata_html}
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by AI-Assisted Cybersecurity Analysis & Governance Platform</p>
            <p>Report generated at {timestamp}</p>
        </div>
    </div>
</body>
</html>
        """
        
        # Determine security score class
        security_score_class = "low"
        if analysis_report.overall_security_score >= 0.8:
            security_score_class = "high"
        elif analysis_report.overall_security_score >= 0.6:
            security_score_class = "medium"
        
        # Generate component results HTML
        component_results_html = ""
        for result in analysis_report.component_results:
            status_class = f"status-{result.status}"
            
            component_results_html += f"""
            <div class="component-result {status_class}">
                <h3>{result.component_name} - {result.analysis_type}</h3>
                <p><strong>Status:</strong> {result.status.title()}</p>
                <p class="execution-time">Execution time: {result.execution_time_seconds:.2f}s</p>
                {f'<p><strong>Error:</strong> {result.error_message}</p>' if result.error_message else ''}
                
                <div class="confidence-bar">
                    <div class="confidence-fill" style="width: {(1.0 if result.status == 'success' else 0.0) * 100}%"></div>
                </div>
                
                <details>
                    <summary>View Details</summary>
                    <pre style="background-color: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto;">
{json.dumps(result.result_data, indent=2, default=str)[:1000]}{'...' if len(json.dumps(result.result_data, default=str)) > 1000 else ''}
                    </pre>
                </details>
            </div>
            """
        
        # Generate insights HTML
        insights_html = ""
        if analysis_report.cross_component_insights:
            for insight in analysis_report.cross_component_insights:
                insights_html += f"""
                <div class="insight">
                    <h4>{insight.insight_type.replace('_', ' ').title()}</h4>
                    <p>{insight.description}</p>
                    <p><strong>Contributing Components:</strong> {', '.join(insight.contributing_components)}</p>
                    <p><strong>Confidence:</strong> {insight.confidence_score:.1%}</p>
                    
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: {insight.confidence_score * 100}%"></div>
                    </div>
                    
                    <strong>Recommendations:</strong>
                    <ul>
                        {''.join(f'<li>{rec}</li>' for rec in insight.recommendations)}
                    </ul>
                </div>
                """
        else:
            insights_html = "<p>No cross-component insights generated.</p>"
        
        # Generate recommendations HTML
        recommendations_html = ""
        for rec in analysis_report.unified_recommendations:
            recommendations_html += f"<li>{rec}</li>"
        
        # Generate metadata HTML
        metadata_html = json.dumps(analysis_report.execution_metadata, indent=2, default=str)
        
        return html_template.format(
            analysis_id=analysis_report.analysis_id,
            target_path=analysis_report.target_path,
            timestamp=analysis_report.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            security_score=int(analysis_report.overall_security_score * 100),
            security_score_class=security_score_class,
            components_count=len(analysis_report.component_results),
            insights_count=len(analysis_report.cross_component_insights),
            execution_time=analysis_report.execution_metadata.get('total_execution_time_seconds', 0),
            analysis_summary=analysis_report.analysis_summary.replace('\n', '<br>'),
            component_results_html=component_results_html,
            insights_html=insights_html,
            recommendations_html=recommendations_html,
            metadata_html=metadata_html
        )
    
    def _generate_executive_summary_content(self, analysis_report: UnifiedAnalysisReport) -> str:
        """Generate executive summary in Markdown format"""
        summary = f"""# Executive Summary: Security Analysis Report

**Analysis ID:** {analysis_report.analysis_id}  
**Target:** {analysis_report.target_path}  
**Date:** {analysis_report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}  
**Overall Security Score:** {analysis_report.overall_security_score:.1%}

## Key Findings

### Security Posture
- **Overall Score:** {analysis_report.overall_security_score:.1%}
- **Components Analyzed:** {len(analysis_report.component_results)}
- **Successful Analyses:** {len([r for r in analysis_report.component_results if r.status == 'success'])}
- **Cross-Component Insights:** {len(analysis_report.cross_component_insights)}

### Component Performance
"""
        
        for result in analysis_report.component_results:
            status_emoji = "✅" if result.status == "success" else "❌" if result.status == "error" else "⚠️"
            summary += f"- {status_emoji} **{result.component_name}** ({result.analysis_type}): {result.status.title()}\n"
        
        summary += "\n## Critical Insights\n\n"
        
        if analysis_report.cross_component_insights:
            for insight in analysis_report.cross_component_insights[:3]:  # Top 3 insights
                summary += f"### {insight.insight_type.replace('_', ' ').title()}\n"
                summary += f"{insight.description}\n\n"
                summary += f"**Confidence:** {insight.confidence_score:.1%}  \n"
                summary += f"**Components:** {', '.join(insight.contributing_components)}\n\n"
        else:
            summary += "No critical cross-component insights identified.\n\n"
        
        summary += "## Top Recommendations\n\n"
        
        for i, rec in enumerate(analysis_report.unified_recommendations[:5], 1):
            summary += f"{i}. {rec}\n"
        
        summary += f"\n## Analysis Metadata\n\n"
        summary += f"- **Total Execution Time:** {analysis_report.execution_metadata.get('total_execution_time_seconds', 0):.2f} seconds\n"
        summary += f"- **Analysis Types:** {', '.join(analysis_report.execution_metadata.get('analysis_types_requested', []))}\n"
        
        return summary
    
    def _generate_correlation_matrix(self, analysis_report: UnifiedAnalysisReport) -> str:
        """Generate component correlation matrix visualization"""
        html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Component Correlation Matrix - {analysis_id}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .matrix {{
            display: grid;
            grid-template-columns: 200px repeat({component_count}, 1fr);
            gap: 2px;
            margin: 20px 0;
        }}
        .matrix-cell {{
            padding: 10px;
            text-align: center;
            border: 1px solid #dee2e6;
            background-color: #f8f9fa;
        }}
        .matrix-header {{
            background-color: #343a40;
            color: white;
            font-weight: bold;
        }}
        .correlation-high {{
            background-color: #28a745;
            color: white;
        }}
        .correlation-medium {{
            background-color: #ffc107;
            color: black;
        }}
        .correlation-low {{
            background-color: #dc3545;
            color: white;
        }}
        .correlation-none {{
            background-color: #6c757d;
            color: white;
        }}
        .legend {{
            display: flex;
            justify-content: center;
            gap: 20px;
            margin: 20px 0;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 5px;
        }}
        .legend-color {{
            width: 20px;
            height: 20px;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Component Correlation Matrix</h1>
            <p>Analysis ID: {analysis_id}</p>
        </div>
        
        <div class="legend">
            <div class="legend-item">
                <div class="legend-color correlation-high"></div>
                <span>High Correlation</span>
            </div>
            <div class="legend-item">
                <div class="legend-color correlation-medium"></div>
                <span>Medium Correlation</span>
            </div>
            <div class="legend-item">
                <div class="legend-color correlation-low"></div>
                <span>Low Correlation</span>
            </div>
            <div class="legend-item">
                <div class="legend-color correlation-none"></div>
                <span>No Data</span>
            </div>
        </div>
        
        <div class="matrix">
            {matrix_html}
        </div>
        
        <div style="margin-top: 30px;">
            <h3>Correlation Analysis</h3>
            <p>This matrix shows the correlation between different analysis components based on:</p>
            <ul>
                <li>Overlapping findings and recommendations</li>
                <li>Cross-component insights generated</li>
                <li>Execution success rates</li>
                <li>Analysis result consistency</li>
            </ul>
        </div>
    </div>
</body>
</html>
        """
        
        # Get component names
        components = [r.component_name for r in analysis_report.component_results]
        component_count = len(components)
        
        # Generate matrix HTML
        matrix_html = ""
        
        # Header row
        matrix_html += '<div class="matrix-cell matrix-header">Component</div>'
        for comp in components:
            matrix_html += f'<div class="matrix-cell matrix-header">{comp.replace("_", " ").title()}</div>'
        
        # Data rows
        for i, comp1 in enumerate(components):
            matrix_html += f'<div class="matrix-cell matrix-header">{comp1.replace("_", " ").title()}</div>'
            
            for j, comp2 in enumerate(components):
                if i == j:
                    # Self-correlation
                    correlation_class = "correlation-high"
                    correlation_value = "1.0"
                else:
                    # Calculate correlation based on insights
                    correlation = self._calculate_component_correlation(comp1, comp2, analysis_report)
                    if correlation >= 0.7:
                        correlation_class = "correlation-high"
                    elif correlation >= 0.4:
                        correlation_class = "correlation-medium"
                    elif correlation > 0:
                        correlation_class = "correlation-low"
                    else:
                        correlation_class = "correlation-none"
                    correlation_value = f"{correlation:.1f}"
                
                matrix_html += f'<div class="matrix-cell {correlation_class}">{correlation_value}</div>'
        
        return html_template.format(
            analysis_id=analysis_report.analysis_id,
            component_count=component_count,
            matrix_html=matrix_html
        )
    
    def _calculate_component_correlation(self, comp1: str, comp2: str, 
                                       analysis_report: UnifiedAnalysisReport) -> float:
        """Calculate correlation score between two components"""
        correlation_score = 0.0
        
        # Check if both components contributed to any insights
        for insight in analysis_report.cross_component_insights:
            if comp1 in insight.contributing_components and comp2 in insight.contributing_components:
                correlation_score += insight.confidence_score
        
        # Check execution success correlation
        comp1_result = next((r for r in analysis_report.component_results if r.component_name == comp1), None)
        comp2_result = next((r for r in analysis_report.component_results if r.component_name == comp2), None)
        
        if comp1_result and comp2_result:
            if comp1_result.status == comp2_result.status == 'success':
                correlation_score += 0.2
        
        return min(1.0, correlation_score)


def create_sample_dashboard_report():
    """Create a sample dashboard report for testing"""
    from .unified_analysis_platform import (
        UnifiedAnalysisReport, ComponentAnalysisResult, CrossComponentInsight
    )
    
    # Create sample data
    sample_report = UnifiedAnalysisReport(
        analysis_id="sample_001",
        timestamp=datetime.now(),
        target_path="/sample/project",
        component_results=[
            ComponentAnalysisResult(
                component_name="python_ai_analyst",
                analysis_type="security_analysis",
                status="success",
                result_data={"confidence_score": 0.85, "security_findings": [{"type": "hardcoded_secret"}]},
                execution_time_seconds=12.5
            ),
            ComponentAnalysisResult(
                component_name="go_security_analyzer",
                analysis_type="sast_analysis",
                status="success",
                result_data={"findings": [{"rule_id": "secret_detection", "severity": "high"}]},
                execution_time_seconds=8.3
            )
        ],
        cross_component_insights=[
            CrossComponentInsight(
                insight_id="security_correlation",
                insight_type="security_validation",
                description="Multiple components detected secret management issues",
                contributing_components=["python_ai_analyst", "go_security_analyzer"],
                confidence_score=0.9,
                recommendations=["Implement secure secret management"],
                supporting_evidence={"overlapping_findings": 2}
            )
        ],
        unified_recommendations=[
            "Implement comprehensive secret management",
            "Add automated security scanning to CI/CD",
            "Regular security training for development team"
        ],
        overall_security_score=0.75,
        analysis_summary="Sample analysis completed successfully",
        execution_metadata={
            "total_execution_time_seconds": 20.8,
            "components_analyzed": 2,
            "successful_analyses": 2
        }
    )
    
    # Generate dashboard
    dashboard = AnalysisDashboard()
    report_path = dashboard.generate_unified_report(sample_report)
    
    print(f"Sample dashboard report generated: {report_path}")
    return report_path


if __name__ == "__main__":
    # Generate sample report for testing
    create_sample_dashboard_report()