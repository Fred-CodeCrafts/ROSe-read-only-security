#!/usr/bin/env python3
"""
Shadow Mode Analysis Controller

This script provides a REST API for managing shadow environments and risk analysis.
It operates in read-only analytical mode, providing comprehensive risk assessments
without making actual infrastructure changes.

Requirements: 3.1
"""

import os
import sys
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

# Add src to Python path
sys.path.insert(0, '/app/src')

from python.agentic_modules.shadow_mode_analyzer import (
    ShadowModeAnalyzer, 
    InfrastructureChange, 
    ShadowEnvironmentConfig,
    RiskAssessment,
    ShadowModeReport
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Initialize Shadow Mode Analyzer
analyzer = ShadowModeAnalyzer(
    base_compose_path="/app/docker-compose.yml",
    shadow_workspace="/shadow_environments",
    analysis_db_path="/analysis/shadow_analysis.db"
)

# HTML template for shadow mode dashboard
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Shadow Mode Analysis Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .card { background-color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .risk-high { border-left: 5px solid #e74c3c; }
        .risk-medium { border-left: 5px solid #f39c12; }
        .risk-low { border-left: 5px solid #27ae60; }
        .button { background-color: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; }
        .button:hover { background-color: #2980b9; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 3px; }
        .status-approved { color: #27ae60; font-weight: bold; }
        .status-rejected { color: #e74c3c; font-weight: bold; }
        .status-review { color: #f39c12; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Shadow Mode Analysis Dashboard</h1>
            <p>Comprehensive Infrastructure Change Risk Analysis</p>
        </div>
        
        <div class="card">
            <h2>📊 System Status</h2>
            <p><strong>Analysis Mode:</strong> Read-Only Shadow Environment</p>
            <p><strong>Active Environments:</strong> <span id="active-envs">0</span></p>
            <p><strong>Completed Analyses:</strong> <span id="completed-analyses">0</span></p>
            <p><strong>System Health:</strong> <span style="color: #27ae60;">✅ Operational</span></p>
        </div>
        
        <div class="card">
            <h2>🔍 Submit Infrastructure Change for Analysis</h2>
            <form id="analysis-form">
                <div class="form-group">
                    <label for="change-id">Change ID:</label>
                    <input type="text" id="change-id" name="change_id" required placeholder="e.g., CHG-2024-001">
                </div>
                
                <div class="form-group">
                    <label for="change-type">Change Type:</label>
                    <select id="change-type" name="change_type" required>
                        <option value="">Select change type...</option>
                        <option value="service_addition">Service Addition</option>
                        <option value="configuration_change">Configuration Change</option>
                        <option value="network_change">Network Change</option>
                        <option value="security_update">Security Update</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="description">Description:</label>
                    <textarea id="description" name="description" rows="3" required placeholder="Describe the proposed infrastructure change..."></textarea>
                </div>
                
                <div class="form-group">
                    <label for="affected-services">Affected Services (comma-separated):</label>
                    <input type="text" id="affected-services" name="affected_services" required placeholder="e.g., web-server, database, cache">
                </div>
                
                <div class="form-group">
                    <label for="submitted-by">Submitted By:</label>
                    <input type="text" id="submitted-by" name="submitted_by" required placeholder="Your name or team">
                </div>
                
                <button type="submit" class="button">🔍 Analyze Change</button>
            </form>
        </div>
        
        <div class="card">
            <h2>📈 Recent Analysis Results</h2>
            <div id="analysis-results">
                <p>No analyses completed yet. Submit a change above to get started.</p>
            </div>
        </div>
    </div>
    
    <script>
        // Update system status
        function updateStatus() {
            fetch('/api/status')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('active-envs').textContent = data.active_environments || 0;
                    document.getElementById('completed-analyses').textContent = data.completed_analyses || 0;
                })
                .catch(error => console.error('Error updating status:', error));
        }
        
        // Submit analysis form
        document.getElementById('analysis-form').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const changeData = {
                change_id: formData.get('change_id'),
                change_type: formData.get('change_type'),
                description: formData.get('description'),
                affected_services: formData.get('affected_services').split(',').map(s => s.trim()),
                submitted_by: formData.get('submitted_by'),
                proposed_config: {}  // Would be populated with actual config
            };
            
            // Show loading state
            const submitButton = e.target.querySelector('button[type="submit"]');
            const originalText = submitButton.textContent;
            submitButton.textContent = '🔄 Analyzing...';
            submitButton.disabled = true;
            
            fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(changeData)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Analysis completed successfully! Check the results below.');
                    loadAnalysisResults();
                    e.target.reset();
                } else {
                    alert('Analysis failed: ' + (data.error || 'Unknown error'));
                }
            })
            .catch(error => {
                console.error('Error submitting analysis:', error);
                alert('Error submitting analysis. Please try again.');
            })
            .finally(() => {
                submitButton.textContent = originalText;
                submitButton.disabled = false;
            });
        });
        
        // Load analysis results
        function loadAnalysisResults() {
            fetch('/api/results')
                .then(response => response.json())
                .then(data => {
                    const resultsDiv = document.getElementById('analysis-results');
                    if (data.results && data.results.length > 0) {
                        resultsDiv.innerHTML = data.results.map(result => `
                            <div class="card risk-${result.risk_level}">
                                <h3>${result.change_id} - ${result.change_type}</h3>
                                <p><strong>Risk Score:</strong> ${result.risk_score}/10</p>
                                <p><strong>Status:</strong> <span class="status-${result.approval_status}">${result.approval_status.toUpperCase()}</span></p>
                                <p><strong>Description:</strong> ${result.description}</p>
                                <p><strong>Analyzed:</strong> ${new Date(result.analyzed_at).toLocaleString()}</p>
                                <details>
                                    <summary>View Detailed Analysis</summary>
                                    <pre>${JSON.stringify(result.detailed_analysis, null, 2)}</pre>
                                </details>
                            </div>
                        `).join('');
                    } else {
                        resultsDiv.innerHTML = '<p>No analyses completed yet.</p>';
                    }
                })
                .catch(error => console.error('Error loading results:', error));
        }
        
        // Initialize dashboard
        updateStatus();
        loadAnalysisResults();
        
        // Refresh status every 30 seconds
        setInterval(updateStatus, 30000);
    </script>
</body>
</html>
"""

@app.route('/')
def dashboard():
    """Serve the shadow mode analysis dashboard"""
    return render_template_string(DASHBOARD_TEMPLATE)

@app.route('/api/status')
def get_status():
    """Get system status information"""
    try:
        status = {
            "status": "operational",
            "active_environments": len(analyzer.active_environments),
            "completed_analyses": len(analyzer.risk_assessments),
            "analysis_mode": "read_only",
            "timestamp": datetime.now().isoformat()
        }
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
def analyze_change():
    """Analyze infrastructure change for risks"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['change_id', 'change_type', 'description', 'affected_services', 'submitted_by']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        # Create infrastructure change object
        change = InfrastructureChange(
            change_id=data['change_id'],
            change_type=data['change_type'],
            description=data['description'],
            affected_services=data['affected_services'],
            proposed_config=data.get('proposed_config', {}),
            current_config=data.get('current_config'),
            risk_level="unknown",  # Will be determined by analysis
            impact_scope=data.get('impact_scope', data['affected_services']),
            submitted_by=data['submitted_by'],
            submitted_at=datetime.now()
        )
        
        logger.info(f"Starting analysis for change: {change.change_id}")
        
        # Perform risk analysis
        risk_assessment = analyzer.analyze_infrastructure_change(change)
        
        # Generate comprehensive report
        report = analyzer.generate_comprehensive_report(change, risk_assessment)
        
        logger.info(f"Analysis completed for change: {change.change_id}")
        
        return jsonify({
            "success": True,
            "change_id": change.change_id,
            "risk_score": risk_assessment.overall_risk_score,
            "approval_status": report.approval_status,
            "report_id": f"report-{change.change_id}",
            "analysis_timestamp": risk_assessment.analysis_timestamp.isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error analyzing change: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/results')
def get_results():
    """Get recent analysis results"""
    try:
        results = []
        
        for change_id, risk_assessment in analyzer.risk_assessments.items():
            # Determine risk level based on score
            if risk_assessment.overall_risk_score >= 7.0:
                risk_level = "high"
            elif risk_assessment.overall_risk_score >= 4.0:
                risk_level = "medium"
            else:
                risk_level = "low"
            
            # Determine approval status
            if risk_assessment.overall_risk_score >= 8.0:
                approval_status = "rejected"
            elif risk_assessment.overall_risk_score >= 5.0:
                approval_status = "needs_review"
            else:
                approval_status = "approved"
            
            result = {
                "change_id": change_id,
                "change_type": "infrastructure_change",  # Would be stored with change
                "description": f"Analysis for change {change_id}",
                "risk_score": round(risk_assessment.overall_risk_score, 1),
                "risk_level": risk_level,
                "approval_status": approval_status,
                "analyzed_at": risk_assessment.analysis_timestamp.isoformat(),
                "detailed_analysis": {
                    "security_risks": len(risk_assessment.security_risks),
                    "performance_risks": len(risk_assessment.performance_risks),
                    "availability_risks": len(risk_assessment.availability_risks),
                    "compliance_risks": len(risk_assessment.compliance_risks),
                    "mitigation_strategies": len(risk_assessment.mitigation_strategies),
                    "confidence_level": risk_assessment.confidence_level
                }
            }
            results.append(result)
        
        # Sort by analysis timestamp (most recent first)
        results.sort(key=lambda x: x['analyzed_at'], reverse=True)
        
        return jsonify({"results": results[:10]})  # Return last 10 results
        
    except Exception as e:
        logger.error(f"Error getting results: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/environments')
def get_environments():
    """Get active shadow environments"""
    try:
        environments = []
        
        for env_id, env_config in analyzer.active_environments.items():
            environment = {
                "environment_id": env_id,
                "created_at": env_config.created_at.isoformat(),
                "ttl_hours": env_config.ttl_hours,
                "network_isolation": env_config.network_isolation,
                "resource_limits": env_config.resource_limits,
                "status": "active"
            }
            environments.append(environment)
        
        return jsonify({"environments": environments})
        
    except Exception as e:
        logger.error(f"Error getting environments: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/rollback/<change_id>')
def get_rollback_plan(change_id):
    """Get rollback plan for a specific change"""
    try:
        if change_id not in analyzer.risk_assessments:
            return jsonify({"error": "Change not found"}), 404
        
        risk_assessment = analyzer.risk_assessments[change_id]
        rollback_plan = risk_assessment.rollback_plan
        
        return jsonify({
            "change_id": change_id,
            "rollback_plan": rollback_plan,
            "generated_at": datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting rollback plan: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "shadow-mode-analyzer",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    })

if __name__ == '__main__':
    logger.info("Starting Shadow Mode Analysis Controller")
    logger.info(f"Dashboard available at: http://localhost:8080")
    logger.info(f"API endpoints available at: http://localhost:8080/api/")
    
    # Run Flask app
    app.run(host='0.0.0.0', port=8080, debug=False)