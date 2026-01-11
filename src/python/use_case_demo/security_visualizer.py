"""
Security Metrics Visualization and Trend Analysis

This module provides comprehensive visualization capabilities for security metrics,
threat patterns, and trend analysis using matplotlib and other visualization libraries.
"""

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import seaborn as sns
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
import json
from pathlib import Path

# Set style for professional-looking plots
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

class SecurityMetricsVisualizer:
    """
    Comprehensive security metrics visualization engine that creates
    professional dashboards and trend analysis charts.
    """
    
    def __init__(self, output_dir: str = "data/analysis"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Configure matplotlib for better output
        plt.rcParams['figure.figsize'] = (12, 8)
        plt.rcParams['font.size'] = 10
        plt.rcParams['axes.titlesize'] = 14
        plt.rcParams['axes.labelsize'] = 12
        plt.rcParams['xtick.labelsize'] = 10
        plt.rcParams['ytick.labelsize'] = 10
        plt.rcParams['legend.fontsize'] = 10
    
    def create_security_overview_dashboard(self, dashboard_data: Dict[str, Any]) -> str:
        """
        Create a comprehensive security overview dashboard.
        
        Args:
            dashboard_data: Dashboard data from SecurityAlertAnalyzer
            
        Returns:
            Path to the generated dashboard image
        """
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Security Overview Dashboard', fontsize=16, fontweight='bold')
        
        metrics = dashboard_data['metrics']
        alerts = dashboard_data['alerts']
        threat_patterns = dashboard_data['threat_patterns']
        
        # 1. Alert Severity Distribution (Pie Chart)
        severity_counts = {}
        for alert in alerts:
            severity = alert['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        if severity_counts:
            colors = {'CRITICAL': '#ff4444', 'HIGH': '#ff8800', 'MEDIUM': '#ffcc00', 'LOW': '#44ff44'}
            ax1.pie(severity_counts.values(), 
                   labels=severity_counts.keys(),
                   colors=[colors.get(k, '#cccccc') for k in severity_counts.keys()],
                   autopct='%1.1f%%',
                   startangle=90)
        ax1.set_title('Alert Severity Distribution')
        
        # 2. Security Score Gauge
        score = metrics['security_score']
        self._create_gauge_chart(ax2, score, 'Security Score')
        
        # 3. Alert Timeline
        if alerts:
            alert_times = [datetime.fromisoformat(alert['timestamp']) for alert in alerts]
            alert_df = pd.DataFrame({'timestamp': alert_times})
            alert_df['date'] = alert_df['timestamp'].dt.date
            daily_counts = alert_df.groupby('date').size()
            
            ax3.plot(daily_counts.index, daily_counts.values, marker='o', linewidth=2)
            ax3.set_title('Daily Alert Trend')
            ax3.set_xlabel('Date')
            ax3.set_ylabel('Number of Alerts')
            ax3.tick_params(axis='x', rotation=45)
        
        # 4. Threat Pattern Frequency
        if threat_patterns:
            pattern_names = [p['pattern_name'] for p in threat_patterns]
            pattern_frequencies = [p['frequency'] for p in threat_patterns]
            
            bars = ax4.bar(range(len(pattern_names)), pattern_frequencies)
            ax4.set_title('Threat Pattern Frequency')
            ax4.set_xlabel('Threat Patterns')
            ax4.set_ylabel('Frequency')
            ax4.set_xticks(range(len(pattern_names)))
            ax4.set_xticklabels(pattern_names, rotation=45, ha='right')
            
            # Color bars based on frequency
            max_freq = max(pattern_frequencies) if pattern_frequencies else 1
            for bar, freq in zip(bars, pattern_frequencies):
                intensity = freq / max_freq
                bar.set_color(plt.cm.Reds(0.3 + 0.7 * intensity))
        
        plt.tight_layout()
        
        # Save the dashboard
        output_path = self.output_dir / f"security_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(output_path)
    
    def _create_gauge_chart(self, ax, value: float, title: str):
        """Create a gauge chart for displaying security score."""
        # Create gauge background
        theta = np.linspace(0, np.pi, 100)
        r = np.ones_like(theta)
        
        # Color segments based on value ranges
        colors = []
        for angle in theta:
            normalized_angle = angle / np.pi
            if normalized_angle < 0.33:  # Red zone (0-33)
                colors.append('#ff4444')
            elif normalized_angle < 0.66:  # Yellow zone (33-66)
                colors.append('#ffcc00')
            else:  # Green zone (66-100)
                colors.append('#44ff44')
        
        # Plot gauge background
        for i in range(len(theta)-1):
            ax.fill_between([theta[i], theta[i+1]], [0, 0], [1, 1], 
                          color=colors[i], alpha=0.3)
        
        # Plot needle
        needle_angle = np.pi * (1 - value / 100)
        ax.plot([needle_angle, needle_angle], [0, 0.8], 'k-', linewidth=4)
        ax.plot(needle_angle, 0, 'ko', markersize=8)
        
        # Configure gauge appearance
        ax.set_xlim(0, np.pi)
        ax.set_ylim(0, 1)
        ax.set_aspect('equal')
        ax.axis('off')
        ax.set_title(f'{title}: {value:.1f}')
        
        # Add value labels
        ax.text(0, -0.1, '0', ha='center', va='top', fontsize=10)
        ax.text(np.pi/2, 1.1, '50', ha='center', va='bottom', fontsize=10)
        ax.text(np.pi, -0.1, '100', ha='center', va='top', fontsize=10)
    
    def create_threat_pattern_analysis(self, threat_patterns: List[Dict[str, Any]]) -> str:
        """
        Create detailed threat pattern analysis visualization.
        
        Args:
            threat_patterns: List of threat pattern data
            
        Returns:
            Path to the generated analysis image
        """
        if not threat_patterns:
            return ""
        
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle('Threat Pattern Analysis', fontsize=16, fontweight='bold')
        
        # 1. Pattern Frequency Distribution
        pattern_names = [p['pattern_name'] for p in threat_patterns]
        frequencies = [p['frequency'] for p in threat_patterns]
        
        ax1.barh(pattern_names, frequencies)
        ax1.set_title('Threat Pattern Frequency')
        ax1.set_xlabel('Frequency')
        
        # 2. Severity Distribution Heatmap
        severity_data = []
        for pattern in threat_patterns:
            severity_dist = pattern['severity_distribution']
            severity_data.append([
                severity_dist.get('CRITICAL', 0),
                severity_dist.get('HIGH', 0),
                severity_dist.get('MEDIUM', 0),
                severity_dist.get('LOW', 0)
            ])
        
        if severity_data:
            severity_df = pd.DataFrame(severity_data, 
                                     columns=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                                     index=pattern_names)
            sns.heatmap(severity_df, annot=True, fmt='d', cmap='Reds', ax=ax2)
            ax2.set_title('Severity Distribution by Pattern')
        
        # 3. Timeline Analysis
        first_seen_dates = []
        last_seen_dates = []
        for pattern in threat_patterns:
            first_seen_dates.append(datetime.fromisoformat(pattern['first_seen']))
            last_seen_dates.append(datetime.fromisoformat(pattern['last_seen']))
        
        if first_seen_dates and last_seen_dates:
            # Create timeline plot
            y_positions = range(len(pattern_names))
            for i, (first, last, name) in enumerate(zip(first_seen_dates, last_seen_dates, pattern_names)):
                ax3.plot([first, last], [i, i], 'o-', linewidth=3, markersize=6)
            
            ax3.set_yticks(y_positions)
            ax3.set_yticklabels(pattern_names)
            ax3.set_title('Pattern Timeline')
            ax3.set_xlabel('Date')
            
            # Format x-axis
            ax3.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d'))
            ax3.xaxis.set_major_locator(mdates.DayLocator(interval=1))
            plt.setp(ax3.xaxis.get_majorticklabels(), rotation=45)
        
        # 4. Mitigation Recommendations Word Cloud (simplified as bar chart)
        all_recommendations = []
        for pattern in threat_patterns:
            all_recommendations.extend(pattern['mitigation_recommendations'])
        
        if all_recommendations:
            # Count recommendation frequency
            rec_counts = {}
            for rec in all_recommendations:
                rec_counts[rec] = rec_counts.get(rec, 0) + 1
            
            # Plot top recommendations
            top_recs = sorted(rec_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            if top_recs:
                rec_names, rec_counts_list = zip(*top_recs)
                ax4.barh(rec_names, rec_counts_list)
                ax4.set_title('Top Mitigation Recommendations')
                ax4.set_xlabel('Frequency')
        
        plt.tight_layout()
        
        # Save the analysis
        output_path = self.output_dir / f"threat_pattern_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(output_path)
    
    def create_trend_analysis(self, dashboard_data: Dict[str, Any], days: int = 30) -> str:
        """
        Create comprehensive trend analysis over specified time period.
        
        Args:
            dashboard_data: Dashboard data from SecurityAlertAnalyzer
            days: Number of days to analyze
            
        Returns:
            Path to the generated trend analysis image
        """
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(16, 12))
        fig.suptitle(f'Security Trend Analysis - Last {days} Days', fontsize=16, fontweight='bold')
        
        alerts = dashboard_data['alerts']
        
        if not alerts:
            # Create empty plots with messages
            for ax in [ax1, ax2, ax3, ax4]:
                ax.text(0.5, 0.5, 'No data available', ha='center', va='center', transform=ax.transAxes)
            plt.tight_layout()
            output_path = self.output_dir / f"trend_analysis_empty_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            return str(output_path)
        
        # Convert alerts to DataFrame for easier analysis
        alert_df = pd.DataFrame(alerts)
        alert_df['timestamp'] = pd.to_datetime(alert_df['timestamp'])
        alert_df['date'] = alert_df['timestamp'].dt.date
        
        # Filter to specified time period
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_alerts = alert_df[alert_df['timestamp'] >= cutoff_date]
        
        # 1. Daily Alert Volume Trend
        daily_counts = recent_alerts.groupby('date').size()
        if not daily_counts.empty:
            ax1.plot(daily_counts.index, daily_counts.values, marker='o', linewidth=2)
            ax1.set_title('Daily Alert Volume')
            ax1.set_xlabel('Date')
            ax1.set_ylabel('Number of Alerts')
            ax1.tick_params(axis='x', rotation=45)
            
            # Add trend line
            x_numeric = np.arange(len(daily_counts))
            z = np.polyfit(x_numeric, daily_counts.values, 1)
            p = np.poly1d(z)
            ax1.plot(daily_counts.index, p(x_numeric), "r--", alpha=0.8, label=f'Trend (slope: {z[0]:.2f})')
            ax1.legend()
        
        # 2. Severity Distribution Over Time
        if not recent_alerts.empty:
            severity_pivot = recent_alerts.pivot_table(
                index='date', 
                columns='severity', 
                values='alert_id', 
                aggfunc='count', 
                fill_value=0
            )
            
            severity_pivot.plot(kind='area', stacked=True, ax=ax2, alpha=0.7)
            ax2.set_title('Severity Distribution Over Time')
            ax2.set_xlabel('Date')
            ax2.set_ylabel('Number of Alerts')
            ax2.legend(title='Severity')
        
        # 3. Alert Type Distribution
        if not recent_alerts.empty:
            type_counts = recent_alerts['alert_type'].value_counts()
            ax3.pie(type_counts.values, labels=type_counts.index, autopct='%1.1f%%')
            ax3.set_title('Alert Type Distribution')
        
        # 4. Security Score Trend (simulated based on alert volume and severity)
        if not recent_alerts.empty:
            # Calculate daily security scores
            daily_scores = []
            dates = []
            
            for date in daily_counts.index:
                day_alerts = recent_alerts[recent_alerts['date'] == date]
                critical_count = len(day_alerts[day_alerts['severity'] == 'CRITICAL'])
                high_count = len(day_alerts[day_alerts['severity'] == 'HIGH'])
                total_count = len(day_alerts)
                
                # Simple scoring algorithm
                score = max(0, 100 - (critical_count * 15) - (high_count * 10) - (total_count * 2))
                daily_scores.append(score)
                dates.append(date)
            
            ax4.plot(dates, daily_scores, marker='o', linewidth=2, color='green')
            ax4.set_title('Security Score Trend')
            ax4.set_xlabel('Date')
            ax4.set_ylabel('Security Score')
            ax4.set_ylim(0, 100)
            ax4.tick_params(axis='x', rotation=45)
            
            # Add horizontal lines for score thresholds
            ax4.axhline(y=80, color='green', linestyle='--', alpha=0.5, label='Good (80+)')
            ax4.axhline(y=60, color='orange', linestyle='--', alpha=0.5, label='Fair (60+)')
            ax4.axhline(y=40, color='red', linestyle='--', alpha=0.5, label='Poor (<40)')
            ax4.legend()
        
        plt.tight_layout()
        
        # Save the trend analysis
        output_path = self.output_dir / f"trend_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(output_path)
    
    def generate_executive_summary_report(self, dashboard_data: Dict[str, Any]) -> str:
        """
        Generate an executive summary report with key visualizations.
        
        Args:
            dashboard_data: Dashboard data from SecurityAlertAnalyzer
            
        Returns:
            Path to the generated executive summary image
        """
        fig = plt.figure(figsize=(16, 20))
        
        # Create a complex layout for executive summary
        gs = fig.add_gridspec(5, 2, height_ratios=[1, 2, 2, 2, 1], hspace=0.3, wspace=0.2)
        
        # Title section
        title_ax = fig.add_subplot(gs[0, :])
        title_ax.text(0.5, 0.5, 'Executive Security Summary Report', 
                     ha='center', va='center', fontsize=24, fontweight='bold')
        title_ax.text(0.5, 0.2, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 
                     ha='center', va='center', fontsize=12)
        title_ax.axis('off')
        
        metrics = dashboard_data['metrics']
        alerts = dashboard_data['alerts']
        threat_patterns = dashboard_data['threat_patterns']
        
        # Key metrics section
        metrics_ax1 = fig.add_subplot(gs[1, 0])
        metrics_ax2 = fig.add_subplot(gs[1, 1])
        
        # Security score gauge
        self._create_gauge_chart(metrics_ax1, metrics['security_score'], 'Overall Security Score')
        
        # Key metrics table
        metrics_data = [
            ['Total Alerts', metrics['total_alerts']],
            ['Critical Alerts', metrics['critical_alerts']],
            ['Resolved Alerts', metrics['resolved_alerts']],
            ['Threat Patterns', metrics['threat_patterns_detected']],
            ['Security Trend', metrics['trend_direction']]
        ]
        
        table = metrics_ax2.table(cellText=metrics_data,
                                colLabels=['Metric', 'Value'],
                                cellLoc='center',
                                loc='center')
        table.auto_set_font_size(False)
        table.set_fontsize(12)
        table.scale(1.2, 1.5)
        metrics_ax2.axis('off')
        metrics_ax2.set_title('Key Security Metrics')
        
        # Alert analysis section
        alert_ax1 = fig.add_subplot(gs[2, 0])
        alert_ax2 = fig.add_subplot(gs[2, 1])
        
        # Severity distribution
        if alerts:
            severity_counts = {}
            for alert in alerts:
                severity = alert['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            colors = {'CRITICAL': '#ff4444', 'HIGH': '#ff8800', 'MEDIUM': '#ffcc00', 'LOW': '#44ff44'}
            alert_ax1.pie(severity_counts.values(), 
                         labels=severity_counts.keys(),
                         colors=[colors.get(k, '#cccccc') for k in severity_counts.keys()],
                         autopct='%1.1f%%')
            alert_ax1.set_title('Alert Severity Distribution')
        
        # Alert type distribution
        if alerts:
            type_counts = {}
            for alert in alerts:
                alert_type = alert['alert_type']
                type_counts[alert_type] = type_counts.get(alert_type, 0) + 1
            
            alert_ax2.bar(type_counts.keys(), type_counts.values())
            alert_ax2.set_title('Alert Type Distribution')
            alert_ax2.tick_params(axis='x', rotation=45)
        
        # Threat pattern section
        threat_ax1 = fig.add_subplot(gs[3, 0])
        threat_ax2 = fig.add_subplot(gs[3, 1])
        
        if threat_patterns:
            # Pattern frequency
            pattern_names = [p['pattern_name'] for p in threat_patterns[:5]]  # Top 5
            frequencies = [p['frequency'] for p in threat_patterns[:5]]
            
            threat_ax1.barh(pattern_names, frequencies)
            threat_ax1.set_title('Top Threat Patterns')
            threat_ax1.set_xlabel('Frequency')
            
            # Recommendations summary
            all_recommendations = []
            for pattern in threat_patterns:
                all_recommendations.extend(pattern['mitigation_recommendations'])
            
            rec_counts = {}
            for rec in all_recommendations:
                rec_counts[rec] = rec_counts.get(rec, 0) + 1
            
            top_recs = sorted(rec_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            if top_recs:
                rec_names, rec_counts_list = zip(*top_recs)
                threat_ax2.barh(rec_names, rec_counts_list)
                threat_ax2.set_title('Top Recommendations')
                threat_ax2.set_xlabel('Frequency')
        
        # Summary section
        summary_ax = fig.add_subplot(gs[4, :])
        
        # Generate executive summary text
        summary_text = self._generate_executive_summary_text(dashboard_data)
        summary_ax.text(0.05, 0.95, summary_text, ha='left', va='top', 
                       transform=summary_ax.transAxes, fontsize=11, 
                       bbox=dict(boxstyle="round,pad=0.3", facecolor="lightgray", alpha=0.5))
        summary_ax.axis('off')
        summary_ax.set_title('Executive Summary', fontsize=14, fontweight='bold')
        
        # Save the executive summary
        output_path = self.output_dir / f"executive_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(output_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return str(output_path)
    
    def _generate_executive_summary_text(self, dashboard_data: Dict[str, Any]) -> str:
        """Generate executive summary text based on dashboard data."""
        metrics = dashboard_data['metrics']
        
        summary_parts = []
        
        # Security posture assessment
        score = metrics['security_score']
        if score >= 80:
            posture = "STRONG"
        elif score >= 60:
            posture = "MODERATE"
        else:
            posture = "NEEDS IMPROVEMENT"
        
        summary_parts.append(f"Security Posture: {posture} (Score: {score:.1f}/100)")
        
        # Alert summary
        total_alerts = metrics['total_alerts']
        critical_alerts = metrics['critical_alerts']
        summary_parts.append(f"Alert Activity: {total_alerts} total alerts, {critical_alerts} critical")
        
        # Trend analysis
        trend = metrics['trend_direction']
        trend_text = {
            'IMPROVING': 'Security metrics show positive improvement',
            'STABLE': 'Security metrics remain stable',
            'DEGRADING': 'Security metrics indicate increased risk'
        }
        summary_parts.append(trend_text.get(trend, 'Trend analysis unavailable'))
        
        # Threat patterns
        pattern_count = metrics['threat_patterns_detected']
        if pattern_count > 0:
            summary_parts.append(f"Threat Intelligence: {pattern_count} distinct threat patterns identified")
        
        # Recommendations
        if critical_alerts > 0:
            summary_parts.append("Immediate Action Required: Address critical alerts and implement recommended mitigations")
        else:
            summary_parts.append("Recommendation: Continue monitoring and maintain current security controls")
        
        return "\n\n".join(summary_parts)

def main():
    """Main function for testing the security visualizer."""
    # This would typically be called with real dashboard data
    sample_data = {
        'alerts': [
            {
                'alert_id': 'alert_1',
                'timestamp': '2024-01-01T10:00:00',
                'severity': 'CRITICAL',
                'alert_type': 'INTRUSION',
                'source_ip': '192.168.1.100',
                'target_ip': '10.0.0.50',
                'description': 'Suspicious network activity detected',
                'threat_indicators': ['unusual_traffic', 'port_scan'],
                'affected_assets': ['web_server'],
                'confidence_score': 0.9,
                'status': 'OPEN'
            }
        ],
        'threat_patterns': [
            {
                'pattern_id': 'pattern_1',
                'pattern_name': 'Intrusion Critical',
                'frequency': 5,
                'severity_distribution': {'CRITICAL': 3, 'HIGH': 2, 'MEDIUM': 0, 'LOW': 0},
                'first_seen': '2024-01-01T08:00:00',
                'last_seen': '2024-01-01T16:00:00',
                'indicators': ['port_scan', 'brute_force'],
                'mitigation_recommendations': ['Implement network segmentation', 'Enable advanced threat detection']
            }
        ],
        'metrics': {
            'total_alerts': 10,
            'critical_alerts': 3,
            'resolved_alerts': 5,
            'false_positives': 1,
            'mean_resolution_time': 4.5,
            'threat_patterns_detected': 2,
            'security_score': 75.0,
            'trend_direction': 'STABLE'
        }
    }
    
    visualizer = SecurityMetricsVisualizer()
    
    print("Generating security visualizations...")
    
    # Generate all visualizations
    dashboard_path = visualizer.create_security_overview_dashboard(sample_data)
    print(f"Security dashboard saved to: {dashboard_path}")
    
    pattern_path = visualizer.create_threat_pattern_analysis(sample_data['threat_patterns'])
    print(f"Threat pattern analysis saved to: {pattern_path}")
    
    trend_path = visualizer.create_trend_analysis(sample_data)
    print(f"Trend analysis saved to: {trend_path}")
    
    executive_path = visualizer.generate_executive_summary_report(sample_data)
    print(f"Executive summary saved to: {executive_path}")

if __name__ == "__main__":
    main()