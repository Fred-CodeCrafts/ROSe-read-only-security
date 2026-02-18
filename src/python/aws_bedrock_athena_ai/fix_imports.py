#!/usr/bin/env python3
"""
Script to fix import issues in the codebase by converting relative imports to absolute imports.
"""

import os
import re
from pathlib import Path

def fix_relative_imports(file_path, package_name="aws_bedrock_athena_ai"):
    """Fix relative imports in a Python file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Pattern to match relative imports like "from aws_bedrock_athena_ai.module import something"
    relative_import_pattern = r'from \.\.([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*) import'
    
    def replace_relative_import(match):
        module_path = match.group(1)
        return f'from {package_name}.{module_path} import'
    
    # Replace relative imports
    content = re.sub(relative_import_pattern, replace_relative_import, content)
    
    # Pattern to match single-level relative imports like "from aws_bedrock_athena_ai.module import something"
    single_relative_pattern = r'from \.([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*) import'
    
    def replace_single_relative_import(match):
        module_path = match.group(1)
        # Determine the current package based on file path
        file_parts = Path(file_path).parts
        if 'aws_bedrock_athena_ai' in file_parts:
            ai_index = file_parts.index('aws_bedrock_athena_ai')
            current_package_parts = file_parts[ai_index:-1]  # Exclude the file name
            current_package = '.'.join(current_package_parts)
            return f'from {current_package}.{module_path} import'
        return match.group(0)  # Return original if we can't determine package
    
    content = re.sub(single_relative_pattern, replace_single_relative_import, content)
    
    # Write back if changed
    if content != original_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed imports in: {file_path}")
        return True
    return False

def main():
    """Fix imports in all Python files."""
    base_path = Path(__file__).parent
    python_files = list(base_path.rglob("*.py"))
    
    fixed_count = 0
    for py_file in python_files:
        if fix_relative_imports(py_file):
            fixed_count += 1
    
    print(f"Fixed imports in {fixed_count} files")

if __name__ == "__main__":
    main()