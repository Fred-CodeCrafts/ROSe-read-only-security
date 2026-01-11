package main

import (
	"context"
	"time"
)

// SecurityEvent represents a security event for analysis
type SecurityEvent struct {
	EventID     string                 `json:"event_id"`
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Severity    string                 `json:"severity"`
	Source      string                 `json:"source"`
	Details     map[string]interface{} `json:"details"`
	RawData     string                 `json:"raw_data"`
}

// SecurityFinding represents a security finding from analysis
type SecurityFinding struct {
	FindingID   string                 `json:"finding_id"`
	RuleID      string                 `json:"rule_id"`
	Severity    string                 `json:"severity"`
	Category    string                 `json:"category"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Location    string                 `json:"location"`
	Details     map[string]interface{} `json:"details"`
	Confidence  float64                `json:"confidence"`
}

// SemgrepAnalysisReport represents results from Semgrep SAST analysis
type SemgrepAnalysisReport struct {
	ScanID      string            `json:"scan_id"`
	Timestamp   time.Time         `json:"timestamp"`
	TargetPath  string            `json:"target_path"`
	Findings    []SecurityFinding `json:"findings"`
	RulesUsed   []string          `json:"rules_used"`
	ScanStats   ScanStatistics    `json:"scan_stats"`
	Status      string            `json:"status"`
}

// SecretAnalysisReport represents results from Gitleaks secret detection
type SecretAnalysisReport struct {
	ScanID      string            `json:"scan_id"`
	Timestamp   time.Time         `json:"timestamp"`
	TargetPath  string            `json:"target_path"`
	Secrets     []SecretFinding   `json:"secrets"`
	ScanStats   ScanStatistics    `json:"scan_stats"`
	Status      string            `json:"status"`
}

// SecretFinding represents a detected secret
type SecretFinding struct {
	FindingID   string `json:"finding_id"`
	RuleID      string `json:"rule_id"`
	File        string `json:"file"`
	LineNumber  int    `json:"line_number"`
	Match       string `json:"match"`
	Secret      string `json:"secret"`
	Commit      string `json:"commit,omitempty"`
	Author      string `json:"author,omitempty"`
	Email       string `json:"email,omitempty"`
	Date        string `json:"date,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

// ThreatIntelligenceReport represents threat analysis results
type ThreatIntelligenceReport struct {
	ReportID        string                 `json:"report_id"`
	Timestamp       time.Time              `json:"timestamp"`
	ThreatLevel     string                 `json:"threat_level"`
	ThreatSources   []string               `json:"threat_sources"`
	Indicators      []ThreatIndicator      `json:"indicators"`
	Recommendations []string               `json:"recommendations"`
	Details         map[string]interface{} `json:"details"`
}

// ThreatIndicator represents a threat indicator
type ThreatIndicator struct {
	Type        string  `json:"type"`
	Value       string  `json:"value"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// RuntimeAnalysisReport represents runtime analysis results from Falco
type RuntimeAnalysisReport struct {
	ReportID    string            `json:"report_id"`
	Timestamp   time.Time         `json:"timestamp"`
	Findings    []SecurityFinding `json:"findings"`
	RulesUsed   []string          `json:"rules_used"`
	ScanStats   ScanStatistics    `json:"scan_stats"`
	Status      string            `json:"status"`
}

// RecommendationReport represents security recommendations
type RecommendationReport struct {
	ReportID        string                 `json:"report_id"`
	Timestamp       time.Time              `json:"timestamp"`
	Recommendations []SecurityRecommendation `json:"recommendations"`
	Priority        string                 `json:"priority"`
	Category        string                 `json:"category"`
}

// SecurityRecommendation represents a security recommendation
type SecurityRecommendation struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Category    string `json:"category"`
	Action      string `json:"action"`
}

// ScanStatistics represents scan statistics
type ScanStatistics struct {
	FilesScanned    int           `json:"files_scanned"`
	LinesScanned    int           `json:"lines_scanned"`
	FindingsCount   int           `json:"findings_count"`
	ScanDuration    time.Duration `json:"scan_duration"`
	RulesExecuted   int           `json:"rules_executed"`
}

// RuntimeLog represents a runtime log entry for Falco analysis
type RuntimeLog struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Rule      string                 `json:"rule"`
	Priority  string                 `json:"priority"`
	Output    string                 `json:"output"`
	Fields    map[string]interface{} `json:"fields"`
}

// OSSSecurityIntelligence defines the interface for OSS security intelligence operations
type OSSSecurityIntelligence interface {
	AnalyzeCodeWithSemgrep(ctx context.Context, codebase string) (*SemgrepAnalysisReport, error)
	AnalyzeSecretsWithGitleaks(ctx context.Context, content string) (*SecretAnalysisReport, error)
	AnalyzeEventsWithWazuh(ctx context.Context, events []SecurityEvent) (*ThreatIntelligenceReport, error)
	AnalyzeRuntimeWithFalco(ctx context.Context, logs []RuntimeLog) (*RuntimeAnalysisReport, error)
	GenerateRecommendations(ctx context.Context, findings []SecurityFinding) (*RecommendationReport, error)
}