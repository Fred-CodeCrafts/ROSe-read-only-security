// Security Intelligence Analyzer - OSS-first security analysis
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	// OSS security analyzer entry point
	workDir := "./temp"
	if err := os.MkdirAll(workDir, 0755); err != nil {
		log.Fatalf("Failed to create work directory: %v", err)
	}

	analyzer := NewOSSSecurityAnalyzer(workDir)
	ctx := context.Background()

	// Example usage
	fmt.Println("OSS Security Intelligence Analyzer initialized")
	fmt.Printf("Work directory: %s\n", workDir)

	// Test basic functionality
	testContent := `
package main

import "fmt"

const apiKey = "sk-1234567890abcdef"

func main() {
	fmt.Println("Hello, World!")
}
`

	// Test secret detection
	report, err := analyzer.AnalyzeSecretsWithGitleaks(ctx, testContent)
	if err != nil {
		log.Printf("Secret analysis failed: %v", err)
	} else {
		fmt.Printf("Secret analysis completed: %d secrets found\n", len(report.Secrets))
	}

	// Test code analysis if semgrep is available
	if cwd, err := os.Getwd(); err == nil {
		srcPath := filepath.Join(cwd, ".")
		if _, err := os.Stat(srcPath); err == nil {
			sastReport, err := analyzer.AnalyzeCodeWithSemgrep(ctx, srcPath)
			if err != nil {
				log.Printf("SAST analysis failed: %v", err)
			} else {
				fmt.Printf("SAST analysis completed: %d findings\n", len(sastReport.Findings))
			}
		}
	}

	fmt.Println("OSS Security Intelligence Analyzer ready for operations")
}