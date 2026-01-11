package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTestCoverageAnalysis tests Property 7: Test Coverage Analysis
// **Feature: ai-cybersecurity-platform, Property 7: Test Coverage Analysis**
// **Validates: Requirements 2.2**
func TestTestCoverageAnalysis(t *testing.T) {
	// Create temporary project directory
	workDir := filepath.Join(os.TempDir(), "coverage_analysis_test")
	err := os.MkdirAll(workDir, 0755)
	require.NoError(t, err)
	defer os.RemoveAll(workDir)

	analyzer := NewOSSSecurityAnalyzer(workDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Property: For any code change analysis, the system should identify test coverage gaps 
	// and generate appropriate test strategy recommendations

	testCases := []struct {
		name                string
		sourceFiles         map[string]string
		testFiles           map[string]string
		expectedGaps        int
		expectedRecommendations int
		description         string
	}{
		{
			name: "go_project_with_missing_tests",
			sourceFiles: map[string]string{
				"main.go": `package main

import "fmt"

func PublicFunction() string {
	return "hello"
}

func privateFunction() int {
	return 42
}

func ComplexFunction(a, b int) (int, error) {
	if a < 0 || b < 0 {
		return 0, fmt.Errorf("negative values not allowed")
	}
	for i := 0; i < a; i++ {
		b += i
	}
	return a + b, nil
}`,
				"utils.go": `package main

func UtilityFunction() bool {
	return true
}`,
			},
			testFiles: map[string]string{
				"main_test.go": `package main

import "testing"

func TestPublicFunction(t *testing.T) {
	result := PublicFunction()
	if result != "hello" {
		t.Errorf("Expected 'hello', got %s", result)
	}
}`,
			},
			expectedGaps:        4, // privateFunction, ComplexFunction, UtilityFunction + complex code block
			expectedRecommendations: 5, // 3 missing tests + complex logic test + general coverage recommendation
			description:         "Should identify missing test coverage for Go functions",
		},
		{
			name: "python_project_with_partial_coverage",
			sourceFiles: map[string]string{
				"calculator.py": `def add(a, b):
    """Add two numbers."""
    return a + b

def subtract(a, b):
    return a - b

def complex_calculation(data):
    result = 0
    for item in data:
        if item > 0:
            result += item * 2
        else:
            result -= item
    return result

def _private_helper():
    return "helper"`,
			},
			testFiles: map[string]string{
				"test_calculator.py": `import unittest
from calculator import add

class TestCalculator(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)`,
			},
			expectedGaps:        3, // subtract, complex_calculation + complex code block (private functions typically not tested)
			expectedRecommendations: 4, // 2 missing tests + complex logic test + general coverage
			description:         "Should identify missing test coverage for Python functions",
		},
		{
			name: "javascript_project_with_good_coverage",
			sourceFiles: map[string]string{
				"math.js": `function multiply(a, b) {
    return a * b;
}

function divide(a, b) {
    if (b === 0) {
        throw new Error("Division by zero");
    }
    return a / b;
}

const square = (x) => x * x;`,
			},
			testFiles: map[string]string{
				"math.test.js": `const { multiply, divide, square } = require('./math');

test('multiply function', () => {
    expect(multiply(2, 3)).toBe(6);
});

test('divide function', () => {
    expect(divide(6, 2)).toBe(3);
});

test('square function', () => {
    expect(square(4)).toBe(16);
});`,
			},
			expectedGaps:        0, // All functions have tests
			expectedRecommendations: 0, // Good coverage, no recommendations needed
			description:         "Should recognize good test coverage",
		},
		{
			name: "mixed_language_project",
			sourceFiles: map[string]string{
				"service.go": `package main

func StartService() error {
	return nil
}`,
				"helper.py": `def format_data(data):
    return str(data).upper()`,
				"client.js": `function connectToAPI() {
    return fetch('/api/data');
}`,
			},
			testFiles: map[string]string{},
			expectedGaps:        3, // All functions missing tests
			expectedRecommendations: 4, // 3 missing tests + general coverage
			description:         "Should handle mixed language projects",
		},
		{
			name: "empty_project",
			sourceFiles: map[string]string{},
			testFiles:   map[string]string{},
			expectedGaps: 0,
			expectedRecommendations: 1, // General coverage improvement recommendation for empty projects
			description: "Should handle empty projects gracefully",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test project structure
			projectDir := filepath.Join(workDir, tc.name)
			err := os.MkdirAll(projectDir, 0755)
			require.NoError(t, err)

			// Create source files
			for filename, content := range tc.sourceFiles {
				filePath := filepath.Join(projectDir, filename)
				err = os.WriteFile(filePath, []byte(content), 0644)
				require.NoError(t, err)
			}

			// Create test files
			for filename, content := range tc.testFiles {
				filePath := filepath.Join(projectDir, filename)
				err = os.WriteFile(filePath, []byte(content), 0644)
				require.NoError(t, err)
			}

			// Test the property: System should identify test coverage gaps
			startTime := time.Now()
			report, err := analyzer.AnalyzeTestCoverage(ctx, projectDir)
			analysisTime := time.Since(startTime)

			// Property validation: Analysis should complete successfully
			assert.NoError(t, err, "Test coverage analysis should complete without error")
			assert.NotNil(t, report, "Coverage analysis report should be generated")

			// Property validation: Report should be comprehensive
			assert.NotEmpty(t, report.ReportID, "Report should have a report ID")
			assert.NotZero(t, report.Timestamp, "Report should have a timestamp")
			assert.Equal(t, projectDir, report.ProjectPath, "Report should reference correct project path")
			assert.Equal(t, "completed", report.Status, "Analysis status should be completed")

			// Property validation: Should complete within reasonable time
			assert.Less(t, analysisTime, 10*time.Second, "Analysis should complete within time limit")

			// Property validation: Should identify expected coverage gaps
			assert.Equal(t, tc.expectedGaps, len(report.CoverageGaps), 
				"Should identify expected number of coverage gaps")

			// Property validation: Should generate appropriate recommendations
			assert.Equal(t, tc.expectedRecommendations, len(report.Recommendations),
				"Should generate expected number of recommendations")

			// Property validation: Coverage gaps should have proper structure
			for _, gap := range report.CoverageGaps {
				assert.NotEmpty(t, gap.GapID, "Gap should have an ID")
				assert.NotEmpty(t, gap.FilePath, "Gap should reference a file")
				assert.NotEmpty(t, gap.FunctionName, "Gap should reference a function")
				assert.Greater(t, gap.LineStart, 0, "Gap should have valid line start")
				assert.GreaterOrEqual(t, gap.LineEnd, gap.LineStart, "Gap line end should be >= line start")
				assert.Contains(t, []string{"low", "medium", "high"}, gap.Severity, 
					"Gap should have valid severity")
				assert.NotEmpty(t, gap.Category, "Gap should have a category")
				assert.NotEmpty(t, gap.Description, "Gap should have a description")
				assert.GreaterOrEqual(t, gap.Confidence, 0.0, "Confidence should be non-negative")
				assert.LessOrEqual(t, gap.Confidence, 1.0, "Confidence should not exceed 1.0")
			}

			// Property validation: Recommendations should be actionable
			for _, rec := range report.Recommendations {
				assert.NotEmpty(t, rec.ID, "Recommendation should have an ID")
				assert.NotEmpty(t, rec.Title, "Recommendation should have a title")
				assert.NotEmpty(t, rec.Description, "Recommendation should have a description")
				assert.Contains(t, []string{"low", "medium", "high"}, rec.Priority,
					"Recommendation should have valid priority")
				assert.NotEmpty(t, rec.Category, "Recommendation should have a category")
				assert.NotEmpty(t, rec.Action, "Recommendation should have an action")
			}

			// Property validation: Coverage statistics should be valid
			stats := report.CoverageStatistics
			assert.GreaterOrEqual(t, stats.TotalLines, 0, "Total lines should be non-negative")
			assert.GreaterOrEqual(t, stats.TotalFunctions, 0, "Total functions should be non-negative")
			assert.GreaterOrEqual(t, stats.CoveredFunctions, 0, "Covered functions should be non-negative")
			assert.LessOrEqual(t, stats.CoveredFunctions, stats.TotalFunctions, 
				"Covered functions should not exceed total functions")
			assert.Equal(t, stats.TotalFunctions, stats.CoveredFunctions+stats.UncoveredFunctions,
				"Function counts should be consistent")
			
			if stats.TotalFunctions > 0 {
				expectedCoverage := float64(stats.CoveredFunctions) / float64(stats.TotalFunctions) * 100
				assert.InDelta(t, expectedCoverage, stats.FunctionCoveragePercent, 0.1,
					"Function coverage percentage should be calculated correctly")
			}
		})
	}
}

// TestDocumentationAnalysisAndRecommendations tests Property 8: Documentation Analysis and Recommendations
// **Feature: ai-cybersecurity-platform, Property 8: Documentation Analysis and Recommendations**
// **Validates: Requirements 2.3**
func TestDocumentationAnalysisAndRecommendations(t *testing.T) {
	workDir := filepath.Join(os.TempDir(), "documentation_analysis_test")
	err := os.MkdirAll(workDir, 0755)
	require.NoError(t, err)
	defer os.RemoveAll(workDir)

	analyzer := NewOSSSecurityAnalyzer(workDir)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Property: For any API change analysis, all related documentation gaps should be identified 
	// and synchronization recommendations should be generated

	testCases := []struct {
		name                    string
		sourceFiles             map[string]string
		documentationFiles      map[string]string
		expectedGaps            int
		expectedSyncIssues      int
		expectedRecommendations int
		description             string
	}{
		{
			name: "well_documented_project",
			sourceFiles: map[string]string{
				"api.go": `package main

// GetUser retrieves a user by ID
func GetUser(id string) (*User, error) {
	return nil, nil
}

// CreateUser creates a new user
func CreateUser(user *User) error {
	return nil
}

// privateHelper is an internal helper function
func privateHelper() string {
	return "helper"
}`,
			},
			documentationFiles: map[string]string{
				"README.md": `# API Documentation

## GetUser
Retrieves a user by ID.

## CreateUser  
Creates a new user in the system.`,
			},
			expectedGaps:            0, // All public functions documented
			expectedSyncIssues:      0, // Documentation is current
			expectedRecommendations: 0, // No issues to fix
			description:             "Should recognize well-documented code",
		},
		{
			name: "undocumented_public_functions",
			sourceFiles: map[string]string{
				"service.py": `def start_service(config):
    """Start the service with given configuration."""
    pass

def stop_service():
    # Missing docstring for public function
    pass

def get_status():
    # Another undocumented public function
    return "running"

def _internal_cleanup():
    # Private function, documentation optional
    pass`,
			},
			documentationFiles: map[string]string{
				"docs.md": `# Service Documentation

## start_service
Starts the service.`,
			},
			expectedGaps:            2, // stop_service, get_status missing docs
			expectedSyncIssues:      0, // No sync issues
			expectedRecommendations: 2, // Recommendations for missing docs
			description:             "Should identify undocumented public functions",
		},
		{
			name: "outdated_documentation",
			sourceFiles: map[string]string{
				"calculator.js": `// Updated recently
function add(a, b) {
    return a + b;
}

function multiply(a, b) {
    return a * b;
}`,
			},
			documentationFiles: map[string]string{
				"old_docs.md": `# Calculator

## add
Adds two numbers.`,
			},
			expectedGaps:            1, // multiply function not documented
			expectedSyncIssues:      1, // Documentation older than source
			expectedRecommendations: 2, // Missing doc + sync issue
			description:             "Should detect outdated documentation",
		},
		{
			name: "mixed_documentation_quality",
			sourceFiles: map[string]string{
				"handlers.go": `package main

// HandleRequest processes incoming requests
func HandleRequest(req *Request) *Response {
	return nil
}

func ProcessData(data []byte) error {
	// Complex function without documentation
	for i := 0; i < len(data); i++ {
		if data[i] == 0 {
			return fmt.Errorf("invalid data")
		}
	}
	return nil
}

func helper() {
	// Private function
}`,
			},
			documentationFiles: map[string]string{
				"api.md": `# API Handlers

## HandleRequest
Processes incoming HTTP requests.`,
			},
			expectedGaps:            1, // ProcessData missing documentation
			expectedSyncIssues:      0, // No sync issues
			expectedRecommendations: 1, // Missing documentation recommendation
			description:             "Should handle mixed documentation quality",
		},
		{
			name: "no_documentation",
			sourceFiles: map[string]string{
				"main.go": `package main

func Main() {
	// Entry point
}

func Initialize() error {
	return nil
}`,
			},
			documentationFiles: map[string]string{},
			expectedGaps:            2, // Both functions undocumented
			expectedSyncIssues:      0, // No docs to sync
			expectedRecommendations: 2, // Need documentation for both
			description:             "Should handle projects with no documentation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test project structure
			projectDir := filepath.Join(workDir, tc.name)
			err := os.MkdirAll(projectDir, 0755)
			require.NoError(t, err)

			// Create source files
			for filename, content := range tc.sourceFiles {
				filePath := filepath.Join(projectDir, filename)
				err = os.WriteFile(filePath, []byte(content), 0644)
				require.NoError(t, err)
			}

			// Create documentation files (with older timestamp if testing sync issues)
			for filename, content := range tc.documentationFiles {
				filePath := filepath.Join(projectDir, filename)
				err = os.WriteFile(filePath, []byte(content), 0644)
				require.NoError(t, err)
				
				// Make documentation older for sync testing
				if tc.expectedSyncIssues > 0 {
					oldTime := time.Now().Add(-24 * time.Hour)
					os.Chtimes(filePath, oldTime, oldTime)
				}
			}

			// Test the property: System should identify documentation gaps and sync issues
			startTime := time.Now()
			report, err := analyzer.AnalyzeDocumentationSynchronization(ctx, projectDir)
			analysisTime := time.Since(startTime)

			// Property validation: Analysis should complete successfully
			assert.NoError(t, err, "Documentation analysis should complete without error")
			assert.NotNil(t, report, "Documentation analysis report should be generated")

			// Property validation: Report should be comprehensive
			assert.NotEmpty(t, report.ReportID, "Report should have a report ID")
			assert.NotZero(t, report.Timestamp, "Report should have a timestamp")
			assert.Equal(t, projectDir, report.ProjectPath, "Report should reference correct project path")
			assert.Equal(t, "completed", report.Status, "Analysis status should be completed")

			// Property validation: Should complete within reasonable time
			assert.Less(t, analysisTime, 10*time.Second, "Analysis should complete within time limit")

			// Property validation: Should identify expected documentation gaps
			assert.Equal(t, tc.expectedGaps, len(report.DocumentationGaps),
				"Should identify expected number of documentation gaps")

			// Property validation: Should identify expected synchronization issues
			assert.Equal(t, tc.expectedSyncIssues, len(report.SynchronizationIssues),
				"Should identify expected number of synchronization issues")

			// Property validation: Should generate appropriate recommendations
			assert.Equal(t, tc.expectedRecommendations, len(report.Recommendations),
				"Should generate expected number of recommendations")

			// Property validation: Documentation gaps should have proper structure
			for _, gap := range report.DocumentationGaps {
				assert.NotEmpty(t, gap.GapID, "Gap should have an ID")
				assert.NotEmpty(t, gap.FilePath, "Gap should reference a file")
				assert.NotEmpty(t, gap.ElementType, "Gap should have element type")
				assert.NotEmpty(t, gap.ElementName, "Gap should reference an element")
				assert.Contains(t, []string{"low", "medium", "high"}, gap.Severity,
					"Gap should have valid severity")
				assert.NotEmpty(t, gap.Description, "Gap should have a description")
				assert.GreaterOrEqual(t, gap.Confidence, 0.0, "Confidence should be non-negative")
				assert.LessOrEqual(t, gap.Confidence, 1.0, "Confidence should not exceed 1.0")
			}

			// Property validation: Synchronization issues should have proper structure
			for _, issue := range report.SynchronizationIssues {
				assert.NotEmpty(t, issue.IssueID, "Issue should have an ID")
				assert.NotEmpty(t, issue.SourceFile, "Issue should reference source file")
				assert.NotEmpty(t, issue.DocFile, "Issue should reference documentation file")
				assert.Contains(t, []string{"outdated", "missing", "inconsistent"}, issue.IssueType,
					"Issue should have valid type")
				assert.NotEmpty(t, issue.Description, "Issue should have a description")
				assert.Contains(t, []string{"low", "medium", "high"}, issue.Severity,
					"Issue should have valid severity")
				assert.GreaterOrEqual(t, issue.Confidence, 0.0, "Confidence should be non-negative")
				assert.LessOrEqual(t, issue.Confidence, 1.0, "Confidence should not exceed 1.0")
			}

			// Property validation: Recommendations should be actionable
			for _, rec := range report.Recommendations {
				assert.NotEmpty(t, rec.ID, "Recommendation should have an ID")
				assert.NotEmpty(t, rec.Title, "Recommendation should have a title")
				assert.NotEmpty(t, rec.Description, "Recommendation should have a description")
				assert.Contains(t, []string{"low", "medium", "high"}, rec.Priority,
					"Recommendation should have valid priority")
				assert.NotEmpty(t, rec.Category, "Recommendation should have a category")
				assert.NotEmpty(t, rec.Action, "Recommendation should have an action")
				assert.NotEmpty(t, rec.FilePath, "Recommendation should reference a file")
			}

			// Property validation: Documentation statistics should be valid
			stats := report.DocumentationStats
			assert.GreaterOrEqual(t, stats.TotalElements, 0, "Total elements should be non-negative")
			assert.GreaterOrEqual(t, stats.DocumentedElements, 0, "Documented elements should be non-negative")
			assert.LessOrEqual(t, stats.DocumentedElements, stats.TotalElements,
				"Documented elements should not exceed total elements")
			assert.Equal(t, stats.TotalElements, stats.DocumentedElements+stats.UndocumentedElements,
				"Element counts should be consistent")
			assert.Equal(t, len(report.SynchronizationIssues), stats.SyncIssues,
				"Sync issues count should match actual issues")

			if stats.TotalElements > 0 {
				expectedPercent := float64(stats.DocumentedElements) / float64(stats.TotalElements) * 100
				assert.InDelta(t, expectedPercent, stats.DocumentationPercent, 0.1,
					"Documentation percentage should be calculated correctly")
			}
		})
	}
}

// TestCoverageAnalysisConsistency tests that coverage analysis is consistent across multiple runs
func TestCoverageAnalysisConsistency(t *testing.T) {
	workDir := filepath.Join(os.TempDir(), "consistency_coverage_test")
	err := os.MkdirAll(workDir, 0755)
	require.NoError(t, err)
	defer os.RemoveAll(workDir)

	analyzer := NewOSSSecurityAnalyzer(workDir)
	ctx := context.Background()

	// Create test project
	projectDir := filepath.Join(workDir, "test_project")
	err = os.MkdirAll(projectDir, 0755)
	require.NoError(t, err)

	// Create source file with known coverage gaps
	sourceContent := `package main

func PublicFunction() string {
	return "test"
}

func AnotherFunction(x int) int {
	if x > 0 {
		return x * 2
	}
	return 0
}`

	err = os.WriteFile(filepath.Join(projectDir, "main.go"), []byte(sourceContent), 0644)
	require.NoError(t, err)

	// Run analysis multiple times to ensure consistency
	var reports []*TestCoverageAnalysisReport
	for i := 0; i < 3; i++ {
		report, err := analyzer.AnalyzeTestCoverage(ctx, projectDir)
		require.NoError(t, err)
		reports = append(reports, report)
	}

	// Property validation: Results should be consistent across runs
	baseReport := reports[0]
	for i, report := range reports[1:] {
		assert.Equal(t, len(baseReport.CoverageGaps), len(report.CoverageGaps),
			"Run %d should have same number of coverage gaps as base run", i+1)
		assert.Equal(t, len(baseReport.Recommendations), len(report.Recommendations),
			"Run %d should have same number of recommendations as base run", i+1)
		assert.Equal(t, baseReport.CoverageStatistics.TotalFunctions, report.CoverageStatistics.TotalFunctions,
			"Run %d should have same total functions as base run", i+1)
	}
}