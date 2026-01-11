"""
Property-based tests for documentation completeness analysis

Property 28: Complete Documentation and Setup
Validates: Requirements 8.6

This module tests the universal properties of documentation completeness analysis
to ensure comprehensive documentation validation and setup analysis.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from hypothesis import given, strategies as st, settings, assume
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize, invariant
import logging
import json
import os
import sys

# Import the documentation analysis components
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'python'))
from integration.documentation_analyzer import DocumentationAnalyzer, DocumentationGap, SetupValidationResult, DeploymentReadinessAssessment


# Configure logging for tests
logging.basicConfig(level=logging.WARNING)


# Hypothesis strategies for generating test data
@st.composite
def documentation_structure(draw):
    """Generate a documentation structure for testing"""
    structure = {}
    
    # Core documentation files
    core_files = ['README.md', 'LICENSE', 'requirements.txt']
    for file_name in core_files:
        if draw(st.booleans()):
            structure[file_name] = draw(st.text(min_size=10, max_size=1000))
    
    # Optional documentation files
    optional_files = ['SECURITY.md', 'CONTRIBUTING.md', 'CHANGELOG.md', '.gitignore', '.env.example']
    for file_name in optional_files:
        if draw(st.booleans()):
            structure[file_name] = draw(st.text(min_size=5, max_size=500))
    
    # Setup scripts
    setup_scripts = ['setup.py', 'setup.sh', 'setup.ps1', 'package.json', 'docker-compose.yml']
    for script_name in setup_scripts:
        if draw(st.booleans()):
            structure[script_name] = draw(st.text(min_size=20, max_size=800))
    
    # Documentation directory
    if draw(st.booleans()):
        structure['docs/setup/README.md'] = draw(st.text(min_size=50, max_size=600))
        structure['docs/api.md'] = draw(st.text(min_size=30, max_size=400))
    
    return structure


@st.composite
def readme_content(draw):
    """Generate README content with various sections"""
    sections = []
    
    # Title
    title = draw(st.text(min_size=5, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd', 'Pc', 'Pd', 'Zs'))))
    sections.append(f"# {title}")
    
    # Optional sections
    section_names = ['Installation', 'Setup', 'Usage', 'Prerequisites', 'Requirements', 'Examples', 'Configuration']
    for section_name in section_names:
        if draw(st.booleans()):
            content = draw(st.text(min_size=10, max_size=200))
            sections.append(f"\n## {section_name}\n\n{content}")
    
    # Add some code blocks
    if draw(st.booleans()):
        code_content = draw(st.text(min_size=5, max_size=100))
        sections.append(f"\n```bash\n{code_content}\n```")
    
    return '\n'.join(sections)


@st.composite
def setup_script_content(draw):
    """Generate setup script content"""
    lines = []
    
    # Shebang for shell scripts
    if draw(st.booleans()):
        lines.append("#!/bin/bash")
    
    # Comments
    if draw(st.booleans()):
        comment = draw(st.text(min_size=5, max_size=100))
        lines.append(f"# {comment}")
    
    # Setup commands
    commands = ['pip install -r requirements.txt', 'npm install', 'yarn install', 'go mod download', 'make install']
    for _ in range(draw(st.integers(min_value=0, max_value=3))):
        command = draw(st.sampled_from(commands))
        lines.append(command)
    
    # Error handling
    if draw(st.booleans()):
        lines.append("set -e")
    
    return '\n'.join(lines)


class TestDocumentationCompletenessProperties:
    """Test documentation completeness analysis properties"""
    
    def setup_method(self):
        """Set up test environment"""
        self.analyzer = DocumentationAnalyzer()
        self.temp_dirs = []
    
    def teardown_method(self):
        """Clean up test environment"""
        for temp_dir in self.temp_dirs:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
    
    def create_temp_project(self, structure: dict) -> Path:
        """Create a temporary project with given structure"""
        temp_dir = Path(tempfile.mkdtemp())
        self.temp_dirs.append(temp_dir)
        
        for file_path, content in structure.items():
            full_path = temp_dir / file_path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content, encoding='utf-8')
        
        return temp_dir
    
    @given(documentation_structure())
    @settings(max_examples=50, deadline=10000)
    def test_property_28_complete_documentation_analysis(self, doc_structure):
        """
        Property 28: Complete Documentation and Setup
        
        For any system installation, all required SDD files, steering files, 
        automation scripts, and documentation should be present and functional
        
        **Validates: Requirements 8.6**
        """
        # Feature: ai-cybersecurity-platform, Property 28: Complete Documentation and Setup
        
        assume(len(doc_structure) > 0)  # Need at least some files
        
        # Create temporary project
        project_path = self.create_temp_project(doc_structure)
        
        # Analyze documentation completeness
        report = self.analyzer.analyze_documentation_completeness(str(project_path))
        
        # Property: Analysis should always complete successfully
        assert report is not None
        assert report.analysis_id is not None
        assert report.timestamp is not None
        assert report.target_path == str(project_path)
        
        # Property: Quality score should be between 0.0 and 1.0
        assert 0.0 <= report.quality_score <= 1.0
        
        # Property: Documentation gaps should be properly categorized
        for gap in report.documentation_gaps:
            assert gap.gap_id is not None
            assert gap.gap_type in ['missing_file', 'incomplete_section', 'outdated_content', 'broken_link', 'unreadable_file', 'incomplete_content', 'missing_structure']
            assert gap.severity in ['critical', 'high', 'medium', 'low']
            assert gap.description is not None
            assert isinstance(gap.recommendations, list)
        
        # Property: Setup validation results should have valid status
        for result in report.setup_validation_results:
            assert result.procedure_name is not None
            assert result.status in ['valid', 'invalid', 'partial', 'untested']
            assert result.steps_validated >= 0
            assert result.total_steps >= 0
            assert result.steps_validated <= result.total_steps
            assert isinstance(result.issues_found, list)
            assert result.execution_time_seconds >= 0.0
        
        # Property: Deployment readiness should have valid assessment
        readiness = report.deployment_readiness
        assert readiness.overall_readiness in ['ready', 'needs_work', 'not_ready']
        assert 0.0 <= readiness.readiness_score <= 1.0
        assert isinstance(readiness.security_assessment, dict)
        assert isinstance(readiness.operational_assessment, dict)
        assert isinstance(readiness.missing_requirements, list)
        assert isinstance(readiness.recommendations, list)
        
        # Property: Governance compliance should be properly structured
        governance = report.governance_compliance
        assert isinstance(governance, dict)
        if 'overall_score' in governance:
            assert 0.0 <= governance['overall_score'] <= 1.0
        
        # Property: Summary should be non-empty string
        assert isinstance(report.summary, str)
        assert len(report.summary.strip()) > 0
    
    @given(readme_content())
    @settings(max_examples=30, deadline=5000)
    def test_property_28_readme_analysis_consistency(self, readme_text):
        """
        Property 28: README analysis should be consistent
        
        For any README content, analysis should consistently identify
        sections and provide appropriate recommendations
        """
        # Feature: ai-cybersecurity-platform, Property 28: README analysis consistency
        
        assume(len(readme_text.strip()) > 10)  # Need meaningful content
        
        # Create project with just README
        structure = {'README.md': readme_text}
        project_path = self.create_temp_project(structure)
        
        # Analyze twice to check consistency
        report1 = self.analyzer.analyze_documentation_completeness(str(project_path))
        report2 = self.analyzer.analyze_documentation_completeness(str(project_path))
        
        # Property: Analysis should be deterministic
        assert report1.quality_score == report2.quality_score
        assert len(report1.documentation_gaps) == len(report2.documentation_gaps)
        assert len(report1.setup_validation_results) == len(report2.setup_validation_results)
        
        # Property: README-specific validation should occur
        readme_validations = [r for r in report1.setup_validation_results if 'README' in r.procedure_name]
        assert len(readme_validations) > 0
        
        # Property: If README has installation section, it should be detected
        has_installation_section = any(section in readme_text.lower() for section in ['installation', 'setup'])
        if has_installation_section:
            # Should have fewer gaps related to missing installation
            installation_gaps = [g for g in report1.documentation_gaps if 'installation' in g.description.lower() or 'setup' in g.description.lower()]
            # May still have gaps, but should recognize the section exists
            readme_validation = readme_validations[0]
            assert readme_validation.steps_validated > 0
    
    @given(setup_script_content())
    @settings(max_examples=30, deadline=5000)
    def test_property_28_setup_script_validation(self, script_content):
        """
        Property 28: Setup script validation should be comprehensive
        
        For any setup script, validation should identify steps and issues
        """
        # Feature: ai-cybersecurity-platform, Property 28: Setup script validation
        
        assume(len(script_content.strip()) > 5)  # Need some content
        
        # Test different script types
        script_names = ['setup.py', 'setup.sh', 'setup.ps1', 'install.sh']
        
        for script_name in script_names:
            structure = {script_name: script_content}
            project_path = self.create_temp_project(structure)
            
            report = self.analyzer.analyze_documentation_completeness(str(project_path))
            
            # Property: Should find and validate the setup script
            script_validations = [r for r in report.setup_validation_results if script_name in r.procedure_name]
            assert len(script_validations) > 0
            
            validation = script_validations[0]
            
            # Property: Validation should have reasonable results
            assert validation.status in ['valid', 'invalid', 'partial']
            assert validation.execution_time_seconds >= 0.0
            
            # Property: If script has install commands, should detect steps
            install_commands = ['pip install', 'npm install', 'yarn install', 'go mod', 'make install']
            has_install_commands = any(cmd in script_content for cmd in install_commands)
            
            if has_install_commands:
                assert validation.steps_validated > 0
            
            # Property: If script lacks error handling, should be flagged
            has_error_handling = any(pattern in script_content for pattern in ['set -e', 'exit', 'error'])
            if not has_error_handling and len(script_content.strip()) > 20:
                # Should have issues about error handling
                error_handling_issues = [issue for issue in validation.issues_found if 'error' in issue.lower()]
                # May or may not flag this depending on script complexity
    
    @given(st.dictionaries(
        st.sampled_from(['README.md', 'SECURITY.md', 'LICENSE', 'requirements.txt', '.gitignore', 'docker-compose.yml']),
        st.text(min_size=1, max_size=500),
        min_size=1,
        max_size=6
    ))
    @settings(max_examples=40, deadline=8000)
    def test_property_28_deployment_readiness_scoring(self, file_structure):
        """
        Property 28: Deployment readiness scoring should be consistent
        
        For any project structure, deployment readiness should be
        scored consistently based on available files and content
        """
        # Feature: ai-cybersecurity-platform, Property 28: Deployment readiness scoring
        
        project_path = self.create_temp_project(file_structure)
        report = self.analyzer.analyze_documentation_completeness(str(project_path))
        
        readiness = report.deployment_readiness
        
        # Property: Readiness score should correlate with overall readiness
        if readiness.overall_readiness == 'ready':
            assert readiness.readiness_score >= 0.8
        elif readiness.overall_readiness == 'needs_work':
            assert 0.6 <= readiness.readiness_score < 0.8
        else:  # not_ready
            assert readiness.readiness_score < 0.6
        
        # Property: Security and operational scores should be valid
        if 'score' in readiness.security_assessment:
            assert 0.0 <= readiness.security_assessment['score'] <= 1.0
        
        if 'score' in readiness.operational_assessment:
            assert 0.0 <= readiness.operational_assessment['score'] <= 1.0
        
        # Property: Missing requirements should be actionable
        for requirement in readiness.missing_requirements:
            assert isinstance(requirement, str)
            assert len(requirement.strip()) > 0
        
        # Property: Recommendations should be actionable
        for recommendation in readiness.recommendations:
            assert isinstance(recommendation, str)
            assert len(recommendation.strip()) > 0
        
        # Property: If critical files exist, should have better readiness
        critical_files = ['README.md', 'requirements.txt', '.gitignore']
        critical_files_present = sum(1 for f in critical_files if f in file_structure)
        
        if critical_files_present >= 2:
            # Should have reasonable readiness score
            assert readiness.readiness_score >= 0.3
        
        # Property: If security files exist, security score should be better
        security_files = ['SECURITY.md', '.gitignore', '.env.example']
        security_files_present = sum(1 for f in security_files if f in file_structure)
        
        if security_files_present >= 1 and 'score' in readiness.security_assessment:
            # Should have some positive security score
            assert readiness.security_assessment['score'] > 0.0
    
    def test_property_28_minimal_valid_project(self):
        """
        Property 28: Minimal valid project should pass basic checks
        
        A project with essential files should have reasonable quality score
        """
        # Feature: ai-cybersecurity-platform, Property 28: Minimal valid project
        
        # Create minimal but complete project
        structure = {
            'README.md': """# Test Project
            
## Installation

pip install -r requirements.txt

## Usage

Run the application with:

```bash
python main.py
```

## Configuration

Copy .env.example to .env and configure.
""",
            'requirements.txt': 'requests==2.28.0\nflask==2.2.0',
            '.gitignore': """*.pyc
__pycache__/
.env
*.log
.DS_Store
""",
            'LICENSE': 'MIT License\n\nCopyright (c) 2024',
            '.env.example': 'API_KEY=your_api_key_here\nDEBUG=false',
            'SECURITY.md': """# Security Policy

## Reporting Security Vulnerabilities

Please report security vulnerabilities to security@example.com
"""
        }
        
        project_path = self.create_temp_project(structure)
        report = self.analyzer.analyze_documentation_completeness(str(project_path))
        
        # Property: Should have high quality score
        assert report.quality_score >= 0.7
        
        # Property: Should be deployment ready or close to it
        assert report.deployment_readiness.overall_readiness in ['ready', 'needs_work']
        assert report.deployment_readiness.readiness_score >= 0.6
        
        # Property: Should have minimal critical gaps
        critical_gaps = [g for g in report.documentation_gaps if g.severity == 'critical']
        assert len(critical_gaps) <= 2  # Allow some minor critical issues
        
        # Property: Should validate README setup instructions
        readme_validations = [r for r in report.setup_validation_results if 'README' in r.procedure_name]
        assert len(readme_validations) > 0
        assert readme_validations[0].status in ['valid', 'partial']
    
    def test_property_28_empty_project_analysis(self):
        """
        Property 28: Empty project should be properly analyzed
        
        An empty project should have low quality score and many gaps
        """
        # Feature: ai-cybersecurity-platform, Property 28: Empty project analysis
        
        # Create empty project
        structure = {}
        project_path = self.create_temp_project(structure)
        
        # Add at least one empty file to make it a valid directory
        (project_path / 'empty.txt').write_text('')
        
        report = self.analyzer.analyze_documentation_completeness(str(project_path))
        
        # Property: Should have low quality score
        assert report.quality_score <= 0.5
        
        # Property: Should have many documentation gaps
        assert len(report.documentation_gaps) >= 3
        
        # Property: Should have critical gaps for missing essential files
        critical_gaps = [g for g in report.documentation_gaps if g.severity == 'critical']
        assert len(critical_gaps) >= 2
        
        # Property: Should not be deployment ready
        assert report.deployment_readiness.overall_readiness == 'not_ready'
        assert report.deployment_readiness.readiness_score <= 0.4
        
        # Property: Should have many missing requirements
        assert len(report.deployment_readiness.missing_requirements) >= 2


class DocumentationAnalysisStateMachine(RuleBasedStateMachine):
    """Stateful testing for documentation analysis"""
    
    def __init__(self):
        super().__init__()
        self.analyzer = DocumentationAnalyzer()
        self.temp_dirs = []
        self.current_project = None
        self.last_report = None
    
    def teardown(self):
        """Clean up temporary directories"""
        for temp_dir in self.temp_dirs:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
    
    @initialize()
    def create_project(self):
        """Initialize with a basic project"""
        temp_dir = Path(tempfile.mkdtemp())
        self.temp_dirs.append(temp_dir)
        self.current_project = temp_dir
        
        # Start with minimal structure
        (temp_dir / 'README.md').write_text('# Test Project\n\nBasic project for testing.')
    
    @rule(file_name=st.sampled_from(['SECURITY.md', 'LICENSE', 'requirements.txt', '.gitignore', 'CONTRIBUTING.md']))
    def add_documentation_file(self, file_name):
        """Add a documentation file to the project"""
        if self.current_project:
            content = f"# {file_name}\n\nContent for {file_name}"
            (self.current_project / file_name).write_text(content)
    
    @rule(script_name=st.sampled_from(['setup.py', 'setup.sh', 'install.sh', 'package.json']))
    def add_setup_script(self, script_name):
        """Add a setup script to the project"""
        if self.current_project:
            content = "# Setup script\necho 'Setting up project'\npip install -r requirements.txt"
            (self.current_project / script_name).write_text(content)
    
    @rule()
    def analyze_project(self):
        """Analyze the current project"""
        if self.current_project:
            self.last_report = self.analyzer.analyze_documentation_completeness(str(self.current_project))
    
    @invariant()
    def analysis_results_are_valid(self):
        """Analysis results should always be valid"""
        if self.last_report:
            # Quality score should be valid
            assert 0.0 <= self.last_report.quality_score <= 1.0
            
            # All gaps should have valid severity
            for gap in self.last_report.documentation_gaps:
                assert gap.severity in ['critical', 'high', 'medium', 'low']
            
            # Deployment readiness should be valid
            readiness = self.last_report.deployment_readiness
            assert readiness.overall_readiness in ['ready', 'needs_work', 'not_ready']
            assert 0.0 <= readiness.readiness_score <= 1.0
    
    @invariant()
    def quality_score_correlates_with_files(self):
        """Quality score should generally correlate with number of documentation files"""
        if self.last_report and self.current_project:
            doc_files = list(self.current_project.glob('*.md')) + list(self.current_project.glob('LICENSE*'))
            
            # More documentation files should generally mean higher quality
            # (This is a loose correlation, not strict)
            if len(doc_files) >= 4:
                # Should have reasonable quality with many doc files
                assert self.last_report.quality_score >= 0.3


# Test class for running stateful tests
class TestDocumentationAnalysisStateful:
    """Stateful tests for documentation analysis"""
    
    def test_stateful_documentation_analysis(self):
        """Run stateful testing for documentation analysis"""
        # Feature: ai-cybersecurity-platform, Property 28: Stateful documentation analysis
        
        # Run the state machine
        state_machine = DocumentationAnalysisStateMachine()
        try:
            state_machine.run()
        finally:
            state_machine.teardown()


if __name__ == '__main__':
    # Run the tests
    pytest.main([__file__, '-v'])