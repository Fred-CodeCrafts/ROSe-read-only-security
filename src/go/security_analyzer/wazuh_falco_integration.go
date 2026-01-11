package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// WazuhClient represents a client for Wazuh SIEM integration
type WazuhClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// FalcoClient represents a client for Falco runtime security integration
type FalcoClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewWazuhClient creates a new Wazuh client
func NewWazuhClient(baseURL, apiKey string) *WazuhClient {
	return &WazuhClient{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// NewFalcoClient creates a new Falco client
func NewFalcoClient(baseURL string) *FalcoClient {
	return &FalcoClient{
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// Enhanced AnalyzeEventsWithWazuh with more sophisticated threat intelligence
func (oss *OSSSecurityAnalyzer) AnalyzeEventsWithWazuhEnhanced(ctx context.Context, events []SecurityEvent) (*ThreatIntelligenceReport, error) {
	reportID := uuid.New().String()
	timestamp := time.Now()

	// Initialize threat analysis variables
	threatLevel := "low"
	threatSources := make([]string, 0)
	indicators := make([]ThreatIndicator, 0)
	recommendations := make([]string, 0)
	
	// Advanced threat pattern analysis
	threatPatterns := map[string]int{
		"brute_force":        0,
		"privilege_escalation": 0,
		"data_exfiltration":  0,
		"malware_activity":   0,
		"network_anomaly":    0,
		"authentication_failure": 0,
	}

	// Process events for advanced threat intelligence
	for _, event := range events {
		// Analyze event patterns
		oss.analyzeEventPatterns(event, threatPatterns)
		
		// Extract threat sources
		if event.Source != "" && !contains(threatSources, event.Source) {
			threatSources = append(threatSources, event.Source)
		}

		// Generate threat indicators based on event analysis
		indicators = append(indicators, oss.generateThreatIndicators(event)...)
	}

	// Determine overall threat level based on patterns
	threatLevel = oss.calculateThreatLevel(threatPatterns, events)

	// Generate contextual recommendations
	recommendations = oss.generateThreatRecommendations(threatPatterns, threatLevel)

	return &ThreatIntelligenceReport{
		ReportID:        reportID,
		Timestamp:       timestamp,
		ThreatLevel:     threatLevel,
		ThreatSources:   threatSources,
		Indicators:      indicators,
		Recommendations: recommendations,
		Details: map[string]interface{}{
			"events_analyzed":    len(events),
			"threat_patterns":    threatPatterns,
			"analysis_method":    "wazuh_enhanced_analysis",
			"confidence_score":   oss.calculateConfidenceScore(threatPatterns),
		},
	}, nil
}

// Enhanced AnalyzeRuntimeWithFalco with more detailed runtime analysis
func (oss *OSSSecurityAnalyzer) AnalyzeRuntimeWithFalcoEnhanced(ctx context.Context, logs []RuntimeLog) (*RuntimeAnalysisReport, error) {
	reportID := uuid.New().String()
	startTime := time.Now()

	findings := make([]SecurityFinding, 0)
	rulesUsed := make([]string, 0)
	
	// Runtime security categories for analysis
	runtimeCategories := map[string]int{
		"file_system":      0,
		"network_activity": 0,
		"process_activity": 0,
		"system_calls":     0,
		"container_escape": 0,
		"privilege_abuse":  0,
	}

	// Process Falco runtime logs with enhanced analysis
	for _, log := range logs {
		// Categorize runtime events
		category := oss.categorizeRuntimeEvent(log)
		if category != "" {
			runtimeCategories[category]++
		}

		// Create enhanced security finding
		finding := SecurityFinding{
			FindingID:   uuid.New().String(),
			RuleID:      log.Rule,
			Severity:    oss.mapFalcoPriorityToSeverity(log.Priority),
			Category:    category,
			Title:       fmt.Sprintf("Runtime Security Event: %s", log.Rule),
			Description: oss.enhanceRuntimeDescription(log),
			Location:    "runtime_environment",
			Details: map[string]interface{}{
				"timestamp":        log.Timestamp,
				"level":           log.Level,
				"priority":        log.Priority,
				"fields":          log.Fields,
				"runtime_context": oss.extractRuntimeContext(log),
			},
			Confidence: oss.calculateRuntimeConfidence(log),
		}

		findings = append(findings, finding)
		
		// Track unique rules used
		if log.Rule != "" && !contains(rulesUsed, log.Rule) {
			rulesUsed = append(rulesUsed, log.Rule)
		}
	}

	scanDuration := time.Since(startTime)
	if scanDuration <= 0 {
		scanDuration = time.Millisecond // Ensure positive duration
	}

	return &RuntimeAnalysisReport{
		ReportID:  reportID,
		Timestamp: startTime,
		Findings:  findings,
		RulesUsed: rulesUsed,
		ScanStats: ScanStatistics{
			FindingsCount: len(findings),
			ScanDuration:  scanDuration,
			RulesExecuted: len(rulesUsed),
		},
		Status: "completed",
	}, nil
}

// Helper methods for enhanced analysis

func (oss *OSSSecurityAnalyzer) analyzeEventPatterns(event SecurityEvent, patterns map[string]int) {
	eventType := strings.ToLower(event.EventType)
	
	switch {
	case strings.Contains(eventType, "auth") && strings.Contains(eventType, "fail"):
		patterns["authentication_failure"]++
		patterns["brute_force"]++
	case strings.Contains(eventType, "privilege") || strings.Contains(eventType, "escalat"):
		patterns["privilege_escalation"]++
	case strings.Contains(eventType, "network") || strings.Contains(eventType, "connection"):
		patterns["network_anomaly"]++
	case strings.Contains(eventType, "malware") || strings.Contains(eventType, "virus"):
		patterns["malware_activity"]++
	case strings.Contains(eventType, "data") && strings.Contains(eventType, "transfer"):
		patterns["data_exfiltration"]++
	}
}

func (oss *OSSSecurityAnalyzer) generateThreatIndicators(event SecurityEvent) []ThreatIndicator {
	indicators := make([]ThreatIndicator, 0)
	
	// Generate indicators based on event type and severity
	switch event.EventType {
	case "authentication_failure":
		indicators = append(indicators, ThreatIndicator{
			Type:        "authentication_anomaly",
			Value:       fmt.Sprintf("Failed authentication from %s", event.Source),
			Confidence:  0.8,
			Description: fmt.Sprintf("Authentication failure detected at %s", event.Timestamp.Format(time.RFC3339)),
		})
	case "network_anomaly":
		indicators = append(indicators, ThreatIndicator{
			Type:        "network_threat",
			Value:       fmt.Sprintf("Network anomaly from %s", event.Source),
			Confidence:  0.7,
			Description: fmt.Sprintf("Unusual network activity detected at %s", event.Timestamp.Format(time.RFC3339)),
		})
	case "privilege_escalation":
		indicators = append(indicators, ThreatIndicator{
			Type:        "privilege_abuse",
			Value:       fmt.Sprintf("Privilege escalation attempt from %s", event.Source),
			Confidence:  0.9,
			Description: fmt.Sprintf("Privilege escalation detected at %s", event.Timestamp.Format(time.RFC3339)),
		})
	}
	
	return indicators
}

func (oss *OSSSecurityAnalyzer) calculateThreatLevel(patterns map[string]int, events []SecurityEvent) string {
	totalEvents := len(events)
	if totalEvents == 0 {
		return "low"
	}
	
	// Calculate threat score based on patterns
	threatScore := 0
	threatScore += patterns["privilege_escalation"] * 10
	threatScore += patterns["malware_activity"] * 8
	threatScore += patterns["data_exfiltration"] * 7
	threatScore += patterns["brute_force"] * 5
	threatScore += patterns["network_anomaly"] * 3
	threatScore += patterns["authentication_failure"] * 2
	
	// Normalize by total events
	normalizedScore := float64(threatScore) / float64(totalEvents)
	
	switch {
	case normalizedScore >= 8.0:
		return "critical"
	case normalizedScore >= 5.0:
		return "high"
	case normalizedScore >= 2.0:
		return "medium"
	default:
		return "low"
	}
}

func (oss *OSSSecurityAnalyzer) generateThreatRecommendations(patterns map[string]int, threatLevel string) []string {
	recommendations := make([]string, 0)
	
	if patterns["authentication_failure"] > 0 {
		recommendations = append(recommendations, "Implement account lockout policies and multi-factor authentication")
	}
	
	if patterns["privilege_escalation"] > 0 {
		recommendations = append(recommendations, "Review and restrict privilege escalation paths, implement least-privilege access")
	}
	
	if patterns["network_anomaly"] > 0 {
		recommendations = append(recommendations, "Implement network segmentation and monitor unusual traffic patterns")
	}
	
	if patterns["malware_activity"] > 0 {
		recommendations = append(recommendations, "Perform malware scan and implement endpoint detection and response (EDR)")
	}
	
	if patterns["data_exfiltration"] > 0 {
		recommendations = append(recommendations, "Implement data loss prevention (DLP) controls and monitor data transfers")
	}
	
	// Add general recommendations based on threat level
	switch threatLevel {
	case "critical":
		recommendations = append(recommendations, "Immediate incident response required - isolate affected systems")
	case "high":
		recommendations = append(recommendations, "Escalate to security team and implement containment measures")
	case "medium":
		recommendations = append(recommendations, "Increase monitoring and review security controls")
	}
	
	return recommendations
}

func (oss *OSSSecurityAnalyzer) calculateConfidenceScore(patterns map[string]int) float64 {
	totalPatterns := 0
	for _, count := range patterns {
		totalPatterns += count
	}
	
	if totalPatterns == 0 {
		return 0.5 // Neutral confidence
	}
	
	// Higher pattern diversity increases confidence
	activePatterns := 0
	for _, count := range patterns {
		if count > 0 {
			activePatterns++
		}
	}
	
	return float64(activePatterns) / float64(len(patterns))
}

func (oss *OSSSecurityAnalyzer) categorizeRuntimeEvent(log RuntimeLog) string {
	rule := strings.ToLower(log.Rule)
	output := strings.ToLower(log.Output)
	
	switch {
	case strings.Contains(rule, "file") || strings.Contains(output, "file"):
		return "file_system"
	case strings.Contains(rule, "network") || strings.Contains(output, "network"):
		return "network_activity"
	case strings.Contains(rule, "process") || strings.Contains(output, "process"):
		return "process_activity"
	case strings.Contains(rule, "syscall") || strings.Contains(output, "syscall"):
		return "system_calls"
	case strings.Contains(rule, "container") || strings.Contains(output, "container"):
		return "container_escape"
	case strings.Contains(rule, "privilege") || strings.Contains(output, "privilege"):
		return "privilege_abuse"
	default:
		return "general_runtime"
	}
}

func (oss *OSSSecurityAnalyzer) mapFalcoPriorityToSeverity(priority string) string {
	switch strings.ToLower(priority) {
	case "emergency", "alert":
		return "critical"
	case "critical", "error":
		return "high"
	case "warning":
		return "medium"
	case "notice", "info", "debug":
		return "low"
	default:
		return "medium"
	}
}

func (oss *OSSSecurityAnalyzer) enhanceRuntimeDescription(log RuntimeLog) string {
	baseDescription := log.Output
	
	// Add context based on rule and fields
	if log.Fields != nil {
		if proc, ok := log.Fields["proc.name"]; ok {
			baseDescription += fmt.Sprintf(" (Process: %v)", proc)
		}
		if user, ok := log.Fields["user.name"]; ok {
			baseDescription += fmt.Sprintf(" (User: %v)", user)
		}
		if container, ok := log.Fields["container.name"]; ok {
			baseDescription += fmt.Sprintf(" (Container: %v)", container)
		}
	}
	
	return baseDescription
}

func (oss *OSSSecurityAnalyzer) extractRuntimeContext(log RuntimeLog) map[string]interface{} {
	context := make(map[string]interface{})
	
	if log.Fields != nil {
		// Extract relevant runtime context
		relevantFields := []string{
			"proc.name", "proc.pid", "proc.cmdline",
			"user.name", "user.uid",
			"container.name", "container.id",
			"fd.name", "fd.type",
			"evt.type", "evt.dir",
		}
		
		for _, field := range relevantFields {
			if value, ok := log.Fields[field]; ok {
				context[field] = value
			}
		}
	}
	
	return context
}

func (oss *OSSSecurityAnalyzer) calculateRuntimeConfidence(log RuntimeLog) float64 {
	confidence := 0.7 // Base confidence
	
	// Increase confidence based on rule specificity
	if log.Rule != "" {
		confidence += 0.1
	}
	
	// Increase confidence based on available context
	if log.Fields != nil && len(log.Fields) > 0 {
		confidence += 0.1
	}
	
	// Adjust based on priority
	switch strings.ToLower(log.Priority) {
	case "emergency", "alert", "critical":
		confidence += 0.1
	case "error":
		confidence += 0.05
	}
	
	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}
	
	return confidence
}

// Utility functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}