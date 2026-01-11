package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TestCoverageAnalysisReport represents test coverage analysis results
type TestCoverageAnalysisReport struct {
	ReportID           string                    `json:"report_id"`
	Timestamp          time.Time                 `json:"timestamp"`
	ProjectPath        string                    `json:"project_path"`
	CoverageGaps       []CoverageGap             `json:"coverage_gaps"`
	CoverageStatistics CoverageStatistics        `json:"coverage_statistics"`
	Recommendations    []TestRecommendation      `json:"recommendations"`
	Status             string                    `json:"status"`
}

// DocumentationAnalysisReport represents documentation analysis results
type DocumentationAnalysisReport struct {
	ReportID              string                      `json:"report_id"`
	Timestamp             time.Time                   `json:"timestamp"`
	ProjectPath           string                      `json:"project_path"`
	DocumentationGaps     []DocumentationGap          `json:"documentation_gaps"`
	SynchronizationIssues []SynchronizationIssue      `json:"synchronization_issues"`
	DocumentationStats    DocumentationStatistics     `json:"documentation_stats"`
	Recommendations       []DocumentationRecommendation `json:"recommendations"`
	Status                string                      `json:"status"`
}

// CoverageGap represents a test coverage gap
type CoverageGap struct {
	GapID       string  `json:"gap_id"`
	FilePath    string  `json:"file_path"`
	FunctionName string `json:"function_name"`
	LineStart   int     `json:"line_start"`
	LineEnd     int     `json:"line_end"`
	Severity    string  `json:"severity"`
	Category    string  `json:"category"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// DocumentationGap represents a documentation gap
type DocumentationGap struct {
	GapID       string  `json:"gap_id"`
	FilePath    string  `json:"file_path"`
	ElementType string  `json:"element_type"` // function, class, interface, etc.
	ElementName string  `json:"element_name"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
	Confidence  float64 `json:"confidence"`
}

// SynchronizationIssue represents a documentation synchronization issue
type SynchronizationIssue struct {
	IssueID     string  `json:"issue_id"`
	SourceFile  string  `json:"source_file"`
	DocFile     string  `json:"doc_file"`
	IssueType   string  `json:"issue_type"` // outdated, missing, inconsistent
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	Confidence  float64 `json:"confidence"`
}

// CoverageStatistics represents test coverage statistics
type CoverageStatistics struct {
	TotalLines        int     `json:"total_lines"`
	CoveredLines      int     `json:"covered_lines"`
	UncoveredLines    int     `json:"uncovered_lines"`
	CoveragePercent   float64 `json:"coverage_percent"`
	TotalFunctions    int     `json:"total_functions"`
	CoveredFunctions  int     `json:"covered_functions"`
	UncoveredFunctions int    `json:"uncovered_functions"`
	FunctionCoveragePercent float64 `json:"function_coverage_percent"`
}

// DocumentationStatistics represents documentation statistics
type DocumentationStatistics struct {
	TotalElements       int     `json:"total_elements"`
	DocumentedElements  int     `json:"documented_elements"`
	UndocumentedElements int    `json:"undocumented_elements"`
	DocumentationPercent float64 `json:"documentation_percent"`
	TotalDocFiles       int     `json:"total_doc_files"`
	OutdatedDocFiles    int     `json:"outdated_doc_files"`
	SyncIssues          int     `json:"sync_issues"`
}

// TestRecommendation represents a test coverage recommendation
type TestRecommendation struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Category    string `json:"category"`
	Action      string `json:"action"`
	FilePath    string `json:"file_path"`
	Function    string `json:"function,omitempty"`
}

// DocumentationRecommendation represents a documentation recommendation
type DocumentationRecommendation struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Category    string `json:"category"`
	Action      string `json:"action"`
	FilePath    string `json:"file_path"`
	Element     string `json:"element,omitempty"`
}

// AnalyzeTestCoverage performs test coverage gap analysis
func (oss *OSSSecurityAnalyzer) AnalyzeTestCoverage(ctx context.Context, projectPath string) (*TestCoverageAnalysisReport, error) {
	reportID := uuid.New().String()
	startTime := time.Now()

	// Validate project path
	if _, err := os.Stat(projectPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("project path does not exist: %s", projectPath)
	}

	// Analyze source files for test coverage gaps
	coverageGaps, err := oss.identifyTestCoverageGaps(projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to identify coverage gaps: %v", err)
	}

	// Calculate coverage statistics
	stats, err := oss.calculateCoverageStatistics(projectPath, coverageGaps)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate coverage statistics: %v", err)
	}

	// Generate test recommendations
	recommendations := oss.generateTestRecommendations(coverageGaps, stats)

	return &TestCoverageAnalysisReport{
		ReportID:           reportID,
		Timestamp:          startTime,
		ProjectPath:        projectPath,
		CoverageGaps:       coverageGaps,
		CoverageStatistics: stats,
		Recommendations:    recommendations,
		Status:             "completed",
	}, nil
}

// AnalyzeDocumentationSynchronization performs documentation synchronization analysis
func (oss *OSSSecurityAnalyzer) AnalyzeDocumentationSynchronization(ctx context.Context, projectPath string) (*DocumentationAnalysisReport, error) {
	reportID := uuid.New().String()
	startTime := time.Now()

	// Validate project path
	if _, err := os.Stat(projectPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("project path does not exist: %s", projectPath)
	}

	// Analyze documentation gaps
	docGaps, err := oss.identifyDocumentationGaps(projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to identify documentation gaps: %v", err)
	}

	// Analyze synchronization issues
	syncIssues, err := oss.identifySynchronizationIssues(projectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to identify synchronization issues: %v", err)
	}

	// Calculate documentation statistics
	stats, err := oss.calculateDocumentationStatistics(projectPath, docGaps, syncIssues)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate documentation statistics: %v", err)
	}

	// Generate documentation recommendations
	recommendations := oss.generateDocumentationRecommendations(docGaps, syncIssues, stats)

	return &DocumentationAnalysisReport{
		ReportID:              reportID,
		Timestamp:             startTime,
		ProjectPath:           projectPath,
		DocumentationGaps:     docGaps,
		SynchronizationIssues: syncIssues,
		DocumentationStats:    stats,
		Recommendations:       recommendations,
		Status:                "completed",
	}, nil
}

// Helper methods for test coverage analysis

func (oss *OSSSecurityAnalyzer) identifyTestCoverageGaps(projectPath string) ([]CoverageGap, error) {
	gaps := make([]CoverageGap, 0)

	// Walk through source files
	err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip test files and non-source files
		if strings.Contains(path, "_test.") || strings.Contains(path, "test_") {
			return nil
		}

		// Analyze supported source file types
		if oss.isSourceFile(path) {
			fileGaps, err := oss.analyzeFileForCoverageGaps(path)
			if err != nil {
				return fmt.Errorf("failed to analyze file %s: %v", path, err)
			}
			gaps = append(gaps, fileGaps...)
		}

		return nil
	})

	return gaps, err
}

func (oss *OSSSecurityAnalyzer) analyzeFileForCoverageGaps(filePath string) ([]CoverageGap, error) {
	gaps := make([]CoverageGap, 0)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(content), "\n")
	
	// Analyze functions for test coverage
	functions := oss.extractFunctions(string(content), filePath)
	
	for _, function := range functions {
		// Check if function has corresponding test
		hasTest := oss.hasCorrespondingTest(filePath, function.Name)
		
		if !hasTest {
			gap := CoverageGap{
				GapID:       uuid.New().String(),
				FilePath:    filePath,
				FunctionName: function.Name,
				LineStart:   function.LineStart,
				LineEnd:     function.LineEnd,
				Severity:    oss.determineCoverageSeverity(function),
				Category:    "missing_test",
				Description: fmt.Sprintf("Function '%s' lacks test coverage", function.Name),
				Confidence:  0.9,
			}
			gaps = append(gaps, gap)
		}
	}

	// Analyze complex code blocks that need testing
	complexBlocks := oss.identifyComplexCodeBlocks(lines, filePath)
	for _, block := range complexBlocks {
		gap := CoverageGap{
			GapID:       uuid.New().String(),
			FilePath:    filePath,
			FunctionName: block.Context,
			LineStart:   block.LineStart,
			LineEnd:     block.LineEnd,
			Severity:    "medium",
			Category:    "complex_logic",
			Description: fmt.Sprintf("Complex logic block requires test coverage: %s", block.Description),
			Confidence:  0.7,
		}
		gaps = append(gaps, gap)
	}

	return gaps, nil
}

func (oss *OSSSecurityAnalyzer) calculateCoverageStatistics(projectPath string, gaps []CoverageGap) (CoverageStatistics, error) {
	stats := CoverageStatistics{}

	// Count total functions and lines in source files
	err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if oss.isSourceFile(path) && !strings.Contains(path, "_test.") {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			lines := strings.Split(string(content), "\n")
			stats.TotalLines += len(lines)

			functions := oss.extractFunctions(string(content), path)
			stats.TotalFunctions += len(functions)
		}

		return nil
	})

	if err != nil {
		return stats, err
	}

	// Calculate coverage based on gaps
	uncoveredFunctions := 0
	for _, gap := range gaps {
		if gap.Category == "missing_test" {
			uncoveredFunctions++
		}
	}

	stats.CoveredFunctions = stats.TotalFunctions - uncoveredFunctions
	stats.UncoveredFunctions = uncoveredFunctions

	if stats.TotalFunctions > 0 {
		stats.FunctionCoveragePercent = float64(stats.CoveredFunctions) / float64(stats.TotalFunctions) * 100
	}

	// Estimate line coverage (simplified)
	estimatedUncoveredLines := uncoveredFunctions * 10 // Rough estimate
	stats.UncoveredLines = estimatedUncoveredLines
	stats.CoveredLines = stats.TotalLines - stats.UncoveredLines

	if stats.TotalLines > 0 {
		stats.CoveragePercent = float64(stats.CoveredLines) / float64(stats.TotalLines) * 100
	}

	return stats, nil
}

func (oss *OSSSecurityAnalyzer) generateTestRecommendations(gaps []CoverageGap, stats CoverageStatistics) []TestRecommendation {
	recommendations := make([]TestRecommendation, 0)

	// Generate recommendations based on coverage gaps
	for _, gap := range gaps {
		var rec TestRecommendation

		switch gap.Category {
		case "missing_test":
			rec = TestRecommendation{
				ID:          uuid.New().String(),
				Title:       fmt.Sprintf("Add Unit Test for %s", gap.FunctionName),
				Description: fmt.Sprintf("Create unit test for function '%s' in %s", gap.FunctionName, gap.FilePath),
				Priority:    gap.Severity,
				Category:    "unit_testing",
				Action:      "create_unit_test",
				FilePath:    gap.FilePath,
				Function:    gap.FunctionName,
			}
		case "complex_logic":
			rec = TestRecommendation{
				ID:          uuid.New().String(),
				Title:       fmt.Sprintf("Add Integration Test for Complex Logic"),
				Description: fmt.Sprintf("Create integration test for complex logic in %s (lines %d-%d)", gap.FilePath, gap.LineStart, gap.LineEnd),
				Priority:    gap.Severity,
				Category:    "integration_testing",
				Action:      "create_integration_test",
				FilePath:    gap.FilePath,
				Function:    gap.FunctionName,
			}
		}

		recommendations = append(recommendations, rec)
	}

	// Add general recommendations based on coverage statistics
	if stats.FunctionCoveragePercent < 80 {
		recommendations = append(recommendations, TestRecommendation{
			ID:          uuid.New().String(),
			Title:       "Improve Overall Test Coverage",
			Description: fmt.Sprintf("Current function coverage is %.1f%%. Target 80%% or higher.", stats.FunctionCoveragePercent),
			Priority:    "high",
			Category:    "coverage_improvement",
			Action:      "increase_test_coverage",
		})
	}

	return recommendations
}

// Helper methods for documentation analysis

func (oss *OSSSecurityAnalyzer) identifyDocumentationGaps(projectPath string) ([]DocumentationGap, error) {
	gaps := make([]DocumentationGap, 0)

	err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if oss.isSourceFile(path) {
			fileGaps, err := oss.analyzeFileForDocumentationGaps(path)
			if err != nil {
				return fmt.Errorf("failed to analyze documentation for file %s: %v", path, err)
			}
			gaps = append(gaps, fileGaps...)
		}

		return nil
	})

	return gaps, err
}

func (oss *OSSSecurityAnalyzer) analyzeFileForDocumentationGaps(filePath string) ([]DocumentationGap, error) {
	gaps := make([]DocumentationGap, 0)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Extract functions and check for documentation
	functions := oss.extractFunctions(string(content), filePath)
	
	for _, function := range functions {
		hasDoc := oss.hasDocumentation(string(content), function)
		
		if !hasDoc && oss.shouldBeDocumented(function) {
			gap := DocumentationGap{
				GapID:       uuid.New().String(),
				FilePath:    filePath,
				ElementType: "function",
				ElementName: function.Name,
				Severity:    oss.determineDocumentationSeverity(function),
				Description: fmt.Sprintf("Function '%s' lacks documentation", function.Name),
				Confidence:  0.9,
			}
			gaps = append(gaps, gap)
		}
	}

	return gaps, nil
}

func (oss *OSSSecurityAnalyzer) identifySynchronizationIssues(projectPath string) ([]SynchronizationIssue, error) {
	issues := make([]SynchronizationIssue, 0)

	// Find documentation files
	docFiles := oss.findDocumentationFiles(projectPath)
	
	// Check for synchronization issues
	for _, docFile := range docFiles {
		// Find corresponding source files
		sourceFiles := oss.findCorrespondingSourceFiles(projectPath, docFile)
		
		for _, sourceFile := range sourceFiles {
			issue := oss.checkSynchronization(sourceFile, docFile)
			if issue != nil {
				issues = append(issues, *issue)
			}
		}
	}

	return issues, nil
}

func (oss *OSSSecurityAnalyzer) calculateDocumentationStatistics(projectPath string, gaps []DocumentationGap, issues []SynchronizationIssue) (DocumentationStatistics, error) {
	stats := DocumentationStatistics{}

	// Count total elements and documentation
	err := filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if oss.isSourceFile(path) {
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}

			functions := oss.extractFunctions(string(content), path)
			stats.TotalElements += len(functions)
		}

		if oss.isDocumentationFile(path) {
			stats.TotalDocFiles++
		}

		return nil
	})

	if err != nil {
		return stats, err
	}

	// Calculate documentation coverage
	stats.UndocumentedElements = len(gaps)
	stats.DocumentedElements = stats.TotalElements - stats.UndocumentedElements
	stats.SyncIssues = len(issues)

	if stats.TotalElements > 0 {
		stats.DocumentationPercent = float64(stats.DocumentedElements) / float64(stats.TotalElements) * 100
	}

	// Count outdated doc files
	for _, issue := range issues {
		if issue.IssueType == "outdated" {
			stats.OutdatedDocFiles++
		}
	}

	return stats, nil
}

func (oss *OSSSecurityAnalyzer) generateDocumentationRecommendations(gaps []DocumentationGap, issues []SynchronizationIssue, stats DocumentationStatistics) []DocumentationRecommendation {
	recommendations := make([]DocumentationRecommendation, 0)

	// Generate recommendations for documentation gaps
	for _, gap := range gaps {
		rec := DocumentationRecommendation{
			ID:          uuid.New().String(),
			Title:       fmt.Sprintf("Add Documentation for %s", gap.ElementName),
			Description: fmt.Sprintf("Add documentation for %s '%s' in %s", gap.ElementType, gap.ElementName, gap.FilePath),
			Priority:    gap.Severity,
			Category:    "missing_documentation",
			Action:      "add_documentation",
			FilePath:    gap.FilePath,
			Element:     gap.ElementName,
		}
		recommendations = append(recommendations, rec)
	}

	// Generate recommendations for synchronization issues
	for _, issue := range issues {
		rec := DocumentationRecommendation{
			ID:          uuid.New().String(),
			Title:       fmt.Sprintf("Fix Documentation Synchronization"),
			Description: fmt.Sprintf("Update %s to synchronize with %s: %s", issue.DocFile, issue.SourceFile, issue.Description),
			Priority:    issue.Severity,
			Category:    "synchronization",
			Action:      "update_documentation",
			FilePath:    issue.DocFile,
		}
		recommendations = append(recommendations, rec)
	}

	return recommendations
}

// Utility methods

type FunctionInfo struct {
	Name      string
	LineStart int
	LineEnd   int
	IsPublic  bool
	IsComplex bool
}

type ComplexBlock struct {
	LineStart   int
	LineEnd     int
	Context     string
	Description string
}

func (oss *OSSSecurityAnalyzer) isSourceFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".go" || ext == ".py" || ext == ".js" || ext == ".ts" || ext == ".java" || ext == ".cpp" || ext == ".c" || ext == ".h"
}

func (oss *OSSSecurityAnalyzer) isDocumentationFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	name := strings.ToLower(filepath.Base(path))
	return ext == ".md" || ext == ".rst" || ext == ".txt" || strings.Contains(name, "readme") || strings.Contains(name, "doc")
}

func (oss *OSSSecurityAnalyzer) extractFunctions(content, filePath string) []FunctionInfo {
	functions := make([]FunctionInfo, 0)
	lines := strings.Split(content, "\n")

	// Simple function extraction based on file type
	ext := strings.ToLower(filepath.Ext(filePath))
	
	switch ext {
	case ".go":
		functions = oss.extractGoFunctions(lines)
	case ".py":
		functions = oss.extractPythonFunctions(lines)
	case ".js", ".ts":
		functions = oss.extractJavaScriptFunctions(lines)
	}

	return functions
}

func (oss *OSSSecurityAnalyzer) extractGoFunctions(lines []string) []FunctionInfo {
	functions := make([]FunctionInfo, 0)
	funcRegex := regexp.MustCompile(`^func\s+(\w+)\s*\(`)

	for i, line := range lines {
		if matches := funcRegex.FindStringSubmatch(line); matches != nil {
			function := FunctionInfo{
				Name:      matches[1],
				LineStart: i + 1,
				LineEnd:   i + 10, // Simplified - would need proper parsing
				IsPublic:  strings.ToUpper(matches[1][:1]) == matches[1][:1],
				IsComplex: strings.Contains(line, "interface") || strings.Contains(line, "error"),
			}
			functions = append(functions, function)
		}
	}

	return functions
}

func (oss *OSSSecurityAnalyzer) extractPythonFunctions(lines []string) []FunctionInfo {
	functions := make([]FunctionInfo, 0)
	funcRegex := regexp.MustCompile(`^def\s+(\w+)\s*\(`)

	for i, line := range lines {
		if matches := funcRegex.FindStringSubmatch(line); matches != nil {
			function := FunctionInfo{
				Name:      matches[1],
				LineStart: i + 1,
				LineEnd:   i + 10, // Simplified
				IsPublic:  !strings.HasPrefix(matches[1], "_"),
				IsComplex: strings.Contains(line, "async") || strings.Contains(line, "*args") || strings.Contains(line, "**kwargs"),
			}
			functions = append(functions, function)
		}
	}

	return functions
}

func (oss *OSSSecurityAnalyzer) extractJavaScriptFunctions(lines []string) []FunctionInfo {
	functions := make([]FunctionInfo, 0)
	funcRegex := regexp.MustCompile(`function\s+(\w+)\s*\(|(\w+)\s*:\s*function\s*\(|(\w+)\s*=>\s*`)

	for i, line := range lines {
		if matches := funcRegex.FindStringSubmatch(line); matches != nil {
			var name string
			for _, match := range matches[1:] {
				if match != "" {
					name = match
					break
				}
			}
			
			if name != "" {
				function := FunctionInfo{
					Name:      name,
					LineStart: i + 1,
					LineEnd:   i + 10, // Simplified
					IsPublic:  true, // JavaScript functions are generally public
					IsComplex: strings.Contains(line, "async") || strings.Contains(line, "Promise"),
				}
				functions = append(functions, function)
			}
		}
	}

	return functions
}

func (oss *OSSSecurityAnalyzer) hasCorrespondingTest(filePath, functionName string) bool {
	// Look for test files
	dir := filepath.Dir(filePath)
	base := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	
	testPatterns := []string{
		filepath.Join(dir, base+"_test.go"),
		filepath.Join(dir, "test_"+base+".py"),
		filepath.Join(dir, base+".test.js"),
		filepath.Join(dir, base+".test.ts"),
	}

	for _, testFile := range testPatterns {
		if content, err := os.ReadFile(testFile); err == nil {
			// Simple check for function name in test file
			if strings.Contains(string(content), functionName) {
				return true
			}
		}
	}

	return false
}

func (oss *OSSSecurityAnalyzer) identifyComplexCodeBlocks(lines []string, filePath string) []ComplexBlock {
	blocks := make([]ComplexBlock, 0)

	// Look for complex patterns
	for i, line := range lines {
		if strings.Contains(line, "for") && strings.Contains(line, "range") {
			blocks = append(blocks, ComplexBlock{
				LineStart:   i + 1,
				LineEnd:     i + 5,
				Context:     "loop",
				Description: "Complex loop logic",
			})
		}
		
		if strings.Contains(line, "if") && (strings.Contains(line, "&&") || strings.Contains(line, "||")) {
			blocks = append(blocks, ComplexBlock{
				LineStart:   i + 1,
				LineEnd:     i + 3,
				Context:     "conditional",
				Description: "Complex conditional logic",
			})
		}
	}

	return blocks
}

func (oss *OSSSecurityAnalyzer) determineCoverageSeverity(function FunctionInfo) string {
	if function.IsPublic && function.IsComplex {
		return "high"
	} else if function.IsPublic {
		return "medium"
	}
	return "low"
}

func (oss *OSSSecurityAnalyzer) hasDocumentation(content string, function FunctionInfo) bool {
	lines := strings.Split(content, "\n")
	
	// Check lines before function for documentation (comments)
	if function.LineStart > 1 {
		prevLine := lines[function.LineStart-2]
		if strings.Contains(prevLine, "//") || strings.Contains(prevLine, "/*") {
			return true
		}
	}
	
	// Check lines after function for documentation (docstrings for Python)
	if function.LineStart < len(lines) {
		nextLine := strings.TrimSpace(lines[function.LineStart])
		if strings.Contains(nextLine, "\"\"\"") || strings.Contains(nextLine, "'''") {
			return true
		}
		
		// Check second line after function definition for docstrings
		if function.LineStart+1 < len(lines) {
			nextLine2 := strings.TrimSpace(lines[function.LineStart+1])
			if strings.Contains(nextLine2, "\"\"\"") || strings.Contains(nextLine2, "'''") {
				return true
			}
		}
	}
	
	return false
}

func (oss *OSSSecurityAnalyzer) shouldBeDocumented(function FunctionInfo) bool {
	return function.IsPublic || function.IsComplex
}

func (oss *OSSSecurityAnalyzer) determineDocumentationSeverity(function FunctionInfo) string {
	if function.IsPublic && function.IsComplex {
		return "high"
	} else if function.IsPublic {
		return "medium"
	}
	return "low"
}

func (oss *OSSSecurityAnalyzer) findDocumentationFiles(projectPath string) []string {
	docFiles := make([]string, 0)
	
	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if oss.isDocumentationFile(path) {
			docFiles = append(docFiles, path)
		}
		
		return nil
	})
	
	return docFiles
}

func (oss *OSSSecurityAnalyzer) findCorrespondingSourceFiles(projectPath, docFile string) []string {
	// Simplified - would need more sophisticated matching
	sourceFiles := make([]string, 0)
	
	filepath.Walk(projectPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if oss.isSourceFile(path) {
			sourceFiles = append(sourceFiles, path)
		}
		
		return nil
	})
	
	return sourceFiles
}

func (oss *OSSSecurityAnalyzer) checkSynchronization(sourceFile, docFile string) *SynchronizationIssue {
	// Simplified synchronization check
	sourceInfo, err := os.Stat(sourceFile)
	if err != nil {
		return nil
	}
	
	docInfo, err := os.Stat(docFile)
	if err != nil {
		return nil
	}
	
	// Check if documentation is older than source
	if docInfo.ModTime().Before(sourceInfo.ModTime()) {
		return &SynchronizationIssue{
			IssueID:     uuid.New().String(),
			SourceFile:  sourceFile,
			DocFile:     docFile,
			IssueType:   "outdated",
			Description: "Documentation is older than source code",
			Severity:    "medium",
			Confidence:  0.8,
		}
	}
	
	return nil
}