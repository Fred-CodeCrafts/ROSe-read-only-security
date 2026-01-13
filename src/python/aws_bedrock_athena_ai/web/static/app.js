// AI Security Analyst - Demo Interface JavaScript

class SecurityAnalystApp {
    constructor() {
        this.apiKey = null;
        this.conversationId = null;
        this.stats = {
            queriesToday: 0,
            avgResponseTime: 0,
            threatsDetected: 0
        };
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.checkApiConnection();
        this.loadExampleQuestions();
        this.updateStats();
    }
    
    setupEventListeners() {
        // Send button and Enter key
        const sendButton = document.getElementById('send-button');
        const questionInput = document.getElementById('question-input');
        
        sendButton.addEventListener('click', () => this.sendQuestion());
        questionInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendQuestion();
            }
        });
        
        // Character counter
        questionInput.addEventListener('input', (e) => {
            const count = e.target.value.length;
            document.querySelector('.character-count').textContent = `${count}/1000`;
        });
        
        // Clear chat
        document.getElementById('clear-chat').addEventListener('click', () => {
            this.clearChat();
        });
        
        // Example questions
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('example-item')) {
                const question = e.target.dataset.question;
                questionInput.value = question;
                this.sendQuestion();
            }
        });
        
        // Copy API key
        document.getElementById('copy-api-key').addEventListener('click', () => {
            this.copyApiKey();
        });
        
        // Modal controls
        document.querySelector('.modal-close').addEventListener('click', () => {
            this.closeModal();
        });
        
        // Tab switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => {
                this.switchTab(e.target.dataset.tab);
            });
        });
        
        // Close modal on outside click
        document.getElementById('results-modal').addEventListener('click', (e) => {
            if (e.target.id === 'results-modal') {
                this.closeModal();
            }
        });
    }
    
    async checkApiConnection() {
        try {
            const response = await fetch('/');
            const data = await response.json();
            
            if (response.ok) {
                this.apiKey = data.demo_api_key;
                document.getElementById('api-key').value = this.apiKey;
                this.setConnectionStatus(true);
            } else {
                this.setConnectionStatus(false);
            }
        } catch (error) {
            console.error('API connection failed:', error);
            this.setConnectionStatus(false);
        }
    }
    
    setConnectionStatus(online) {
        const statusDot = document.getElementById('connection-status');
        const statusText = document.getElementById('status-text');
        
        if (online) {
            statusDot.className = 'status-dot online';
            statusText.textContent = 'Connected';
        } else {
            statusDot.className = 'status-dot offline';
            statusText.textContent = 'Disconnected';
        }
    }
    
    async loadExampleQuestions() {
        try {
            const response = await fetch('/api/v1/security/examples', {
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`
                }
            });
            
            if (response.ok) {
                const data = await response.json();
                this.updateExampleQuestions(data.examples);
            }
        } catch (error) {
            console.error('Failed to load examples:', error);
        }
    }
    
    updateExampleQuestions(examples) {
        const container = document.getElementById('example-questions');
        container.innerHTML = '';
        
        examples.slice(0, 4).forEach(question => {
            const item = document.createElement('div');
            item.className = 'example-item';
            item.dataset.question = question;
            item.innerHTML = `
                <i class="fas fa-question-circle"></i>
                ${question}
            `;
            container.appendChild(item);
        });
    }
    
    async sendQuestion() {
        const input = document.getElementById('question-input');
        const question = input.value.trim();
        
        if (!question) return;
        
        // Add user message to chat
        this.addMessage(question, 'user');
        
        // Clear input
        input.value = '';
        document.querySelector('.character-count').textContent = '0/1000';
        
        // Show loading
        this.showLoading(true);
        
        try {
            const startTime = Date.now();
            
            const response = await fetch('/api/v1/security/question', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.apiKey}`
                },
                body: JSON.stringify({
                    question: question,
                    conversation_id: this.conversationId,
                    user_role: 'analyst'
                })
            });
            
            const data = await response.json();
            const responseTime = Date.now() - startTime;
            
            if (response.ok) {
                this.handleSuccessResponse(data, responseTime);
            } else {
                this.handleErrorResponse(data);
            }
            
        } catch (error) {
            console.error('Request failed:', error);
            this.addMessage('Sorry, I encountered an error processing your question. Please try again.', 'bot');
        } finally {
            this.showLoading(false);
        }
    }
    
    handleSuccessResponse(data, responseTime) {
        this.conversationId = data.conversation_id;
        
        if (data.needs_clarification) {
            // Handle clarification request
            const clarificationText = `I need some clarification to better understand your question:\n\n${data.clarification_questions.join('\n')}`;
            this.addMessage(clarificationText, 'bot');
        } else {
            // Handle full analysis response
            const summary = data.executive_summary || 'Analysis completed successfully.';
            this.addMessage(summary, 'bot');
            
            // Show detailed results if available
            if (data.technical_details || data.recommendations) {
                this.showDetailedResults(data);
            }
            
            // Update stats
            this.updateStatsAfterQuery(responseTime, data);
        }
    }
    
    handleErrorResponse(error) {
        const errorMessage = error.error_message || 'An error occurred processing your request.';
        this.addMessage(`Error: ${errorMessage}`, 'bot');
    }
    
    addMessage(text, sender) {
        const messagesContainer = document.getElementById('chat-messages');
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${sender}-message`;
        
        const avatar = sender === 'bot' ? 'fas fa-robot' : 'fas fa-user';
        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        
        messageDiv.innerHTML = `
            <div class="message-avatar">
                <i class="${avatar}"></i>
            </div>
            <div class="message-content">
                <div class="message-text">${text}</div>
                <div class="message-time">${time}</div>
            </div>
        `;
        
        messagesContainer.appendChild(messageDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
    
    showDetailedResults(data) {
        // Populate modal with results
        this.populateExecutiveSummary(data.executive_summary);
        this.populateTechnicalDetails(data.technical_details);
        this.populateRecommendations(data.recommendations);
        this.populateVisualizations(data.visualizations);
        
        // Show modal
        document.getElementById('results-modal').classList.add('show');
    }
    
    populateExecutiveSummary(summary) {
        const container = document.getElementById('executive-summary');
        container.innerHTML = `
            <div class="summary-content">
                <h3>Executive Summary</h3>
                <p>${summary || 'No executive summary available.'}</p>
            </div>
        `;
    }
    
    populateTechnicalDetails(details) {
        const container = document.getElementById('technical-details');
        
        if (!details) {
            container.innerHTML = '<p>No technical details available.</p>';
            return;
        }
        
        container.innerHTML = `
            <div class="technical-content">
                <h3>Technical Analysis</h3>
                <div class="detail-grid">
                    <div class="detail-item">
                        <label>Threats Found:</label>
                        <span>${details.threats_found || 0}</span>
                    </div>
                    <div class="detail-item">
                        <label>Risk Score:</label>
                        <span>${details.risk_score || 'N/A'}</span>
                    </div>
                </div>
                ${details.analysis_details ? `<div class="analysis-details">${JSON.stringify(details.analysis_details, null, 2)}</div>` : ''}
            </div>
        `;
    }
    
    populateRecommendations(recommendations) {
        const container = document.getElementById('recommendations-list');
        
        if (!recommendations || recommendations.length === 0) {
            container.innerHTML = '<p>No recommendations available.</p>';
            return;
        }
        
        const recommendationsHtml = recommendations.map(rec => `
            <div class="recommendation-item">
                <div class="rec-header">
                    <h4>${rec.description}</h4>
                    <span class="priority-badge priority-${rec.priority.toLowerCase()}">${rec.priority}</span>
                </div>
                <div class="rec-details">
                    <p><strong>Business Impact:</strong> ${rec.business_impact}</p>
                    <div class="implementation-steps">
                        <strong>Implementation Steps:</strong>
                        <ul>
                            ${rec.implementation_steps.map(step => `<li>${step}</li>`).join('')}
                        </ul>
                    </div>
                </div>
            </div>
        `).join('');
        
        container.innerHTML = `
            <div class="recommendations-content">
                <h3>Security Recommendations</h3>
                ${recommendationsHtml}
            </div>
        `;
    }
    
    populateVisualizations(visualizations) {
        const container = document.getElementById('visualizations-container');
        
        if (!visualizations || visualizations.length === 0) {
            container.innerHTML = '<p>No visualizations available.</p>';
            return;
        }
        
        const visualizationsHtml = visualizations.map(viz => `
            <div class="visualization-item">
                <h4>${viz.title}</h4>
                <div class="viz-placeholder">
                    <i class="fas fa-chart-${viz.type === 'bar' ? 'bar' : 'pie'}"></i>
                    <p>Visualization: ${viz.title}</p>
                    <small>Type: ${viz.type}</small>
                </div>
            </div>
        `).join('');
        
        container.innerHTML = `
            <div class="visualizations-content">
                <h3>Data Visualizations</h3>
                ${visualizationsHtml}
            </div>
        `;
    }
    
    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
        
        // Update tab panes
        document.querySelectorAll('.tab-pane').forEach(pane => {
            pane.classList.remove('active');
        });
        document.getElementById(`${tabName}-tab`).classList.add('active');
    }
    
    closeModal() {
        document.getElementById('results-modal').classList.remove('show');
    }
    
    showLoading(show) {
        const overlay = document.getElementById('loading-overlay');
        if (show) {
            overlay.classList.add('show');
        } else {
            overlay.classList.remove('show');
        }
    }
    
    clearChat() {
        const messagesContainer = document.getElementById('chat-messages');
        messagesContainer.innerHTML = `
            <div class="message bot-message">
                <div class="message-avatar">
                    <i class="fas fa-robot"></i>
                </div>
                <div class="message-content">
                    <div class="message-text">
                        Chat cleared. How can I help you with your security analysis?
                    </div>
                    <div class="message-time">Just now</div>
                </div>
            </div>
        `;
        this.conversationId = null;
    }
    
    copyApiKey() {
        const apiKeyInput = document.getElementById('api-key');
        apiKeyInput.select();
        document.execCommand('copy');
        
        // Show feedback
        const button = document.getElementById('copy-api-key');
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fas fa-check"></i>';
        setTimeout(() => {
            button.innerHTML = originalText;
        }, 1000);
    }
    
    updateStatsAfterQuery(responseTime, data) {
        this.stats.queriesToday++;
        this.stats.avgResponseTime = Math.round((this.stats.avgResponseTime + responseTime) / 2);
        
        if (data.technical_details && data.technical_details.threats_found > 0) {
            this.stats.threatsDetected += data.technical_details.threats_found;
        }
        
        this.updateStats();
    }
    
    updateStats() {
        document.getElementById('queries-today').textContent = this.stats.queriesToday;
        document.getElementById('avg-response-time').textContent = `${this.stats.avgResponseTime}ms`;
        document.getElementById('threats-detected').textContent = this.stats.threatsDetected;
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new SecurityAnalystApp();
});

// Add some CSS for the new elements
const additionalStyles = `
<style>
.detail-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin: 1rem 0;
}

.detail-item {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem;
    background: var(--background-color);
    border-radius: 4px;
}

.recommendation-item {
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1rem;
}

.rec-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.priority-badge {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 600;
}

.priority-high {
    background: var(--danger-color);
    color: white;
}

.priority-medium {
    background: var(--warning-color);
    color: white;
}

.priority-low {
    background: var(--success-color);
    color: white;
}

.visualization-item {
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1rem;
    text-align: center;
}

.viz-placeholder {
    padding: 2rem;
    background: var(--background-color);
    border-radius: 4px;
}

.viz-placeholder i {
    font-size: 3rem;
    color: var(--primary-color);
    margin-bottom: 1rem;
}

.analysis-details {
    background: var(--background-color);
    padding: 1rem;
    border-radius: 4px;
    font-family: monospace;
    font-size: 0.9rem;
    white-space: pre-wrap;
    margin-top: 1rem;
}
</style>
`;

document.head.insertAdjacentHTML('beforeend', additionalStyles);