package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAnalysisDrivenSecurityScanning tests Property 6: Analysis-Driven Security Scanning
// **Feature: ai-cybersecurity-platform, Property 6: Analysis-Driven Security Scanning**
// **Validates: Requirements 2.1**
func TestAnalysisDrivenSecurityScanning(t *testing.T) {
	// Create temporary work directory
	workDir := filepath.Join(os.TempDir(), "security_test")
	err := os.MkdirAll(workDir, 0755)
	require.NoError(t, err)
	defer os.RemoveAll(workDir)

	analyzer := NewOSSSecurityAnalyzer(workDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Property: For any file analysis operation, SAST scans should be automatically triggered 
	// and generate comprehensive security analysis reports within defined time limits

	testCases := []struct {
		name        string
		codeContent string
		expectError bool
	}{
		{
			name: "valid_go_code",
			codeContent: `package main
import "fmt"
func main() {
	fmt.Println("Hello, World!")
}`,
			expectError: false,
		},
		{
			name: "python_code_with_potential_issue",
			codeContent: `import os
password = "hardcoded_password"
os.system("rm -rf /")`,
			expectError: false,
		},
		{
			name: "javascript_code",
			codeContent: `const express = require('express');
const app = express();
app.get('/', (req, res) => {
	res.send('Hello World!');
});`,
			expectError: false,
		},
		{
			name: "empty_directory",
			codeContent: "",
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test directory with code
			testDir := filepath.Join(workDir, tc.name)
			err := os.MkdirAll(testDir, 0755)
			require.NoError(t, err)

			if tc.codeContent != "" {
				// Determine file extension based on content
				var filename string
				if strings.Contains(tc.codeContent, "package main") {
					filename = "main.go"
				} else if strings.Contains(tc.codeContent, "import os") {
					filename = "script.py"
				} else if strings.Contains(tc.codeContent, "require(") {
					filename = "app.js"
				} else {
					filename = "code.txt"
				}

				err = os.WriteFile(filepath.Join(testDir, filename), []byte(tc.codeContent), 0644)
				require.NoError(t, err)
			}

			// Test the property: SAST scans should be automatically triggered
			startTime := time.Now()
			report, err := analyzer.AnalyzeCodeWithSemgrep(ctx, testDir)
			scanDuration := time.Since(startTime)

			if tc.expectError {
				assert.Error(t, err)
				return
			}

			// Property validation: Analysis should complete successfully
			assert.NoError(t, err, "SAST analysis should complete without error")
			assert.NotNil(t, report, "Analysis report should be generated")

			// Property validation: Report should be comprehensive
			assert.NotEmpty(t, report.ScanID, "Report should have a scan ID")
			assert.NotZero(t, report.Timestamp, "Report should have a timestamp")
			assert.Equal(t, testDir, report.TargetPath, "Report should reference correct target path")
			assert.Equal(t, "completed", report.Status, "Scan status should be completed")

			// Property validation: Should complete within reasonable time limits (30 seconds)
			assert.Less(t, scanDuration, 30*time.Second, "Scan should complete within time limit")

			// Property validation: Scan statistics should be populated
			assert.GreaterOrEqual(t, report.ScanStats.FindingsCount, 0, "Findings count should be non-negative")
			assert.Greater(t, report.ScanStats.ScanDuration, time.Duration(0), "Scan duration should be positive")

			// Property validation: Findings should have proper structure if any exist
			for _, finding := range report.Findings {
				assert.NotEmpty(t, finding.FindingID, "Finding should have an ID")
				assert.NotEmpty(t, finding.RuleID, "Finding should reference a rule")
				assert.Contains(t, []string{"low", "medium", "high", "critical"}, finding.Severity, "Finding should have valid severity")
				assert.NotEmpty(t, finding.Title, "Finding should have a title")
				assert.NotEmpty(t, finding.Description, "Finding should have a description")
				assert.GreaterOrEqual(t, finding.Confidence, 0.0, "Confidence should be non-negative")
				assert.LessOrEqual(t, finding.Confidence, 1.0, "Confidence should not exceed 1.0")
			}
		})
	}
}

// TestSecretDetectionAndAnalysis tests Property 9: Secret Detection and Analysis
// **Feature: ai-cybersecurity-platform, Property 9: Secret Detection and Analysis**
// **Validates: Requirements 2.4**
func TestSecretDetectionAndAnalysis(t *testing.T) {
	workDir := filepath.Join(os.TempDir(), "secret_test")
	err := os.MkdirAll(workDir, 0755)
	require.NoError(t, err)
	defer os.RemoveAll(workDir)

	analyzer := NewOSSSecurityAnalyzer(workDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Property: For any content analysis containing secret patterns (API keys, passwords, tokens), 
	// the system should detect and report the findings with remediation recommendations

	testCases := []struct {
		name            string
		content         string
		expectSecrets   bool
		expectedPattern string
	}{
		{
			name:            "aws_access_key",
			content:         `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`,
			expectSecrets:   true,
			expectedPattern: "aws",
		},
		{
			name:            "github_token",
			content:         `GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz`,
			expectSecrets:   true,
			expectedPattern: "github",
		},
		{
			name:            "generic_api_key",
			content:         `api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"`,
			expectSecrets:   true,
			expectedPattern: "api",
		},
		{
			name:            "password_in_code",
			content:         `password = "super_secret_password_123"`,
			expectSecrets:   true,
			expectedPattern: "password",
		},
		{
			name:            "clean_code",
			content:         `package main\nimport "fmt"\nfunc main() {\n\tfmt.Println("Hello, World!")\n}`,
			expectSecrets:   false,
			expectedPattern: "",
		},
		{
			name:            "empty_content",
			content:         "",
			expectSecrets:   false,
			expectedPattern: "",
		},
		{
			name:            "multiple_secrets",
			content:         `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nGITHUB_TOKEN=ghp_abcdef123456\napi_key="sk-test123"`,
			expectSecrets:   true,
			expectedPattern: "multiple",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the property: Secret detection should identify secret patterns
			startTime := time.Now()
			report, err := analyzer.AnalyzeSecretsWithGitleaks(ctx, tc.content)
			scanDuration := time.Since(startTime)

			// Property validation: Analysis should complete successfully
			assert.NoError(t, err, "Secret analysis should complete without error")
			assert.NotNil(t, report, "Secret analysis report should be generated")

			// Property validation: Report should be comprehensive
			assert.NotEmpty(t, report.ScanID, "Report should have a scan ID")
			assert.NotZero(t, report.Timestamp, "Report should have a timestamp")
			assert.Equal(t, "completed", report.Status, "Scan status should be completed")

			// Property validation: Should complete within reasonable time limits
			assert.Less(t, scanDuration, 30*time.Second, "Secret scan should complete within time limit")

			// Property validation: Secret detection accuracy
			if tc.expectSecrets {
				assert.Greater(t, len(report.Secrets), 0, "Should detect secrets when present")
				assert.Greater(t, report.ScanStats.FindingsCount, 0, "Findings count should reflect detected secrets")

				// Property validation: Each secret finding should have proper structure
				for _, secret := range report.Secrets {
					assert.NotEmpty(t, secret.FindingID, "Secret finding should have an ID")
					assert.NotEmpty(t, secret.RuleID, "Secret finding should reference a rule")
					assert.NotEmpty(t, secret.Match, "Secret finding should have a match")
					assert.NotEmpty(t, secret.Fingerprint, "Secret finding should have a fingerprint")
					assert.GreaterOrEqual(t, secret.LineNumber, 0, "Line number should be non-negative")
				}
			} else {
				assert.Equal(t, 0, len(report.Secrets), "Should not detect secrets in clean content")
				assert.Equal(t, 0, report.ScanStats.FindingsCount, "Findings count should be zero for clean content")
			}

			// Property validation: Scan statistics should be populated
			assert.GreaterOrEqual(t, report.ScanStats.FindingsCount, 0, "Findings count should be non-negative")
			assert.Greater(t, report.ScanStats.ScanDuration, time.Duration(0), "Scan duration should be positive")
		})
	}
}

// TestSecretDetectionConsistency tests that secret detection is consistent across multiple runs
func TestSecretDetectionConsistency(t *testing.T) {
	workDir := filepath.Join(os.TempDir(), "consistency_test")
	err := os.MkdirAll(workDir, 0755)
	require.NoError(t, err)
	defer os.RemoveAll(workDir)

	analyzer := NewOSSSecurityAnalyzer(workDir)
	ctx := context.Background()

	// Test content with known secrets
	testContent := `
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz
`

	// Run analysis multiple times to ensure consistency
	var reports []*SecretAnalysisReport
	for i := 0; i < 3; i++ {
		report, err := analyzer.AnalyzeSecretsWithGitleaks(ctx, testContent)
		require.NoError(t, err)
		reports = append(reports, report)
	}

	// Property validation: Results should be consistent across runs
	baseReport := reports[0]
	for i, report := range reports[1:] {
		assert.Equal(t, len(baseReport.Secrets), len(report.Secrets), 
			"Run %d should detect same number of secrets as base run", i+1)
		assert.Equal(t, baseReport.ScanStats.FindingsCount, report.ScanStats.FindingsCount,
			"Run %d should have same findings count as base run", i+1)
	}
}