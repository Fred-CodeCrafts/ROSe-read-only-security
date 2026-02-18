"""
Code Analysis Module for ROSe AI Security Analyst

Provides code context to the AI for security analysis.
"""

import os
from pathlib import Path
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class CodeContextProvider:
    """Provides code context for AI analysis"""
    
    def __init__(self, workspace_root: str = None):
        """Initialize with workspace root directory"""
        if workspace_root is None:
            # Try to find workspace root (look for common markers)
            current = Path.cwd()
            while current != current.parent:
                if (current / '.git').exists() or (current / 'requirements.txt').exists():
                    workspace_root = str(current)
                    break
                current = current.parent
            else:
                workspace_root = str(Path.cwd())
        
        self.workspace_root = Path(workspace_root)
        logger.info(f"Code context workspace: {self.workspace_root}")
    
    def get_code_summary(self, max_files: int = 20) -> str:
        """Get a summary of the codebase structure"""
        try:
            summary_parts = []
            summary_parts.append(f"# Codebase: {self.workspace_root.name}\n")
            
            # Count files by type
            file_counts = self._count_files_by_type()
            if file_counts:
                summary_parts.append("## File Statistics:")
                for ext, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                    summary_parts.append(f"- {ext}: {count} files")
                summary_parts.append("")
            
            # Get directory structure
            structure = self._get_directory_structure(max_depth=3)
            if structure:
                summary_parts.append("## Directory Structure:")
                summary_parts.append(structure)
                summary_parts.append("")
            
            # Get key files
            key_files = self._get_key_files(max_files)
            if key_files:
                summary_parts.append("## Key Files:")
                for file_path, size in key_files:
                    summary_parts.append(f"- {file_path} ({size} bytes)")
                summary_parts.append("")
            
            return "\n".join(summary_parts)
        
        except Exception as e:
            logger.error(f"Error generating code summary: {e}")
            return f"# Codebase: {self.workspace_root.name}\n(Error generating summary)"
    
    def _count_files_by_type(self) -> Dict[str, int]:
        """Count files by extension"""
        counts = {}
        try:
            for file_path in self.workspace_root.rglob('*'):
                if file_path.is_file() and not self._should_ignore(file_path):
                    ext = file_path.suffix or '(no extension)'
                    counts[ext] = counts.get(ext, 0) + 1
        except Exception as e:
            logger.error(f"Error counting files: {e}")
        return counts
    
    def _get_directory_structure(self, max_depth: int = 3) -> str:
        """Get directory structure as a tree"""
        lines = []
        try:
            self._build_tree(self.workspace_root, "", lines, 0, max_depth)
        except Exception as e:
            logger.error(f"Error building directory tree: {e}")
        return "\n".join(lines[:50])  # Limit to 50 lines
    
    def _build_tree(self, path: Path, prefix: str, lines: List[str], depth: int, max_depth: int):
        """Recursively build directory tree"""
        if depth >= max_depth:
            return
        
        try:
            items = sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name))
            items = [item for item in items if not self._should_ignore(item)][:20]  # Limit items
            
            for i, item in enumerate(items):
                is_last = i == len(items) - 1
                current_prefix = "└── " if is_last else "├── "
                lines.append(f"{prefix}{current_prefix}{item.name}")
                
                if item.is_dir() and depth < max_depth - 1:
                    extension = "    " if is_last else "│   "
                    self._build_tree(item, prefix + extension, lines, depth + 1, max_depth)
        except PermissionError:
            pass
    
    def _get_key_files(self, max_files: int = 20) -> List[tuple]:
        """Get list of key files (Python, config, docs)"""
        key_extensions = {'.py', '.md', '.txt', '.yml', '.yaml', '.json', '.toml'}
        key_names = {'README', 'requirements', 'setup', 'config', '.env'}
        
        files = []
        try:
            for file_path in self.workspace_root.rglob('*'):
                if file_path.is_file() and not self._should_ignore(file_path):
                    # Check if it's a key file
                    if (file_path.suffix in key_extensions or 
                        any(name.lower() in file_path.name.lower() for name in key_names)):
                        try:
                            size = file_path.stat().st_size
                            rel_path = file_path.relative_to(self.workspace_root)
                            files.append((str(rel_path), size))
                        except:
                            pass
        except Exception as e:
            logger.error(f"Error getting key files: {e}")
        
        # Sort by relevance (README first, then by name)
        files.sort(key=lambda x: (
            0 if 'README' in x[0] else 1,
            1 if 'requirements' in x[0] else 2,
            x[0]
        ))
        
        return files[:max_files]
    
    def _should_ignore(self, path: Path) -> bool:
        """Check if path should be ignored"""
        ignore_patterns = {
            '.git', '__pycache__', '.pytest_cache', 'node_modules',
            '.venv', 'venv', '.env', '.hypothesis', '.mypy_cache',
            '.tox', 'dist', 'build', '*.pyc', '.DS_Store'
        }
        
        name = path.name
        return any(pattern in name or name.startswith('.') and name != '.env' 
                  for pattern in ignore_patterns)
    
    def get_security_context(self) -> str:
        """Get security-specific context about the codebase"""
        context_parts = []
        
        # Look for security-related files
        security_files = []
        try:
            for pattern in ['*security*', '*auth*', '*credential*', '*secret*', '*key*']:
                for file_path in self.workspace_root.rglob(pattern):
                    if file_path.is_file() and not self._should_ignore(file_path):
                        rel_path = file_path.relative_to(self.workspace_root)
                        security_files.append(str(rel_path))
        except Exception as e:
            logger.error(f"Error finding security files: {e}")
        
        if security_files:
            context_parts.append("## Security-Related Files:")
            for file_path in security_files[:10]:
                context_parts.append(f"- {file_path}")
            context_parts.append("")
        
        # Check for common security configurations
        config_files = ['.env', '.env.example', 'config.yml', 'secrets.yml']
        found_configs = []
        for config in config_files:
            if (self.workspace_root / config).exists():
                found_configs.append(config)
        
        if found_configs:
            context_parts.append("## Configuration Files:")
            for config in found_configs:
                context_parts.append(f"- {config}")
            context_parts.append("")
        
        return "\n".join(context_parts) if context_parts else ""
    
    def analyze_file_for_risks(self, file_path: str) -> List[str]:
        """Analyze a specific file for potential security risks"""
        risks = []
        try:
            full_path = self.workspace_root / file_path
            if not full_path.exists():
                return risks
            
            content = full_path.read_text(encoding='utf-8', errors='ignore')
            
            # Simple pattern matching for common issues
            risk_patterns = {
                'hardcoded_secret': ['password =', 'api_key =', 'secret =', 'token ='],
                'sql_injection': ['execute(', 'cursor.execute', 'raw SQL'],
                'command_injection': ['os.system(', 'subprocess.call', 'eval('],
                'insecure_random': ['random.random()', 'random.randint'],
                'debug_mode': ['DEBUG = True', 'debug=True'],
            }
            
            for risk_type, patterns in risk_patterns.items():
                for pattern in patterns:
                    if pattern.lower() in content.lower():
                        risks.append(f"{risk_type}: Found '{pattern}'")
        
        except Exception as e:
            logger.error(f"Error analyzing file {file_path}: {e}")
        
        return risks


def create_enhanced_prompt(user_question: str, workspace_root: str = None) -> str:
    """Create an enhanced prompt with code context"""
    provider = CodeContextProvider(workspace_root)
    
    # Build context
    context_parts = [
        "You are ROSe, an AI Security Analyst with access to the user's codebase.",
        "",
        "# User's Codebase Context:",
        provider.get_code_summary(),
    ]
    
    # Add security context if relevant
    if any(keyword in user_question.lower() for keyword in ['security', 'risk', 'vulnerability', 'threat']):
        security_context = provider.get_security_context()
        if security_context:
            context_parts.append(security_context)
    
    # Add user question
    context_parts.extend([
        "",
        "# User Question:",
        user_question,
        "",
        "# Instructions:",
        "Provide a concise security assessment in bullet points.",
        "List only the top 3-5 most critical issues.",
        "Be specific and actionable."
    ])
    
    return "\n".join(context_parts)
