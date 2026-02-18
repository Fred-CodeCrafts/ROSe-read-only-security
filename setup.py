#!/usr/bin/env python3
"""
ROSe AI Security Analyst - Setup Script

Install ROSe as a global command-line tool.
After installation, simply run: rose
"""

from setuptools import setup, find_packages
from setuptools.command.develop import develop
from setuptools.command.install import install
from pathlib import Path
import sys
import os


def print_post_install_message():
    """Print instructions after installation"""
    scripts_dir = os.path.join(sys.prefix, 'Scripts' if sys.platform == 'win32' else 'bin')
    
    print("\n" + "="*70)
    print("✅ ROSe AI Security Analyst installed successfully!")
    print("="*70)
    
    print("\n📝 USAGE:")
    print("  python rose.py analyze /path/to/your/project")
    print("  python rose.py analyze . --types security --report")
    
    print("\n⚡ OPTIONAL: Add to PATH for 'rose' command")
    print(f"\n  Add this directory to your PATH:")
    print(f"  {scripts_dir}")
    
    if sys.platform == 'win32':
        print("\n  Windows Instructions:")
        print("  1. Press Win + X → System → Advanced system settings")
        print("  2. Environment Variables → Path → Edit → New")
        print(f"  3. Paste: {scripts_dir}")
        print("  4. Restart terminal")
        print("  5. Use: rose analyze .")
    else:
        print("\n  Linux/Mac Instructions:")
        print(f"  echo 'export PATH=\"{scripts_dir}:$PATH\"' >> ~/.bashrc")
        print("  source ~/.bashrc")
        print("  rose analyze .")
    
    print("\n📚 Documentation: See README.md")
    print("="*70 + "\n")


class PostDevelopCommand(develop):
    """Post-installation for development mode."""
    def run(self):
        develop.run(self)
        print_post_install_message()


class PostInstallCommand(install):
    """Post-installation for installation mode."""
    def run(self):
        install.run(self)
        print_post_install_message()


# Read the README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    requirements = [
        line.strip() 
        for line in requirements_file.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="rose-security-analyst",
    version="1.0.0",
    description="ROSe AI Security Analyst - Read-Only Security analysis powered by AI",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="ROSe Team",
    author_email="security@rose-analyst.dev",
    url="https://github.com/yourusername/rose-security-analyst",
    license="MIT",
    
    # Package discovery
    packages=find_packages(where="src/python"),
    package_dir={"": "src/python"},
    
    # Include non-Python files
    include_package_data=True,
    package_data={
        "": ["*.yaml", "*.yml", "*.json", "*.md", "*.txt"],
    },
    
    # Dependencies - filter out platform-specific packages
    install_requires=[
        req for req in requirements 
        if not req.startswith('semgrep')  # Semgrep doesn't support Windows
    ],
    
    # Python version requirement
    python_requires=">=3.8",
    
    # Entry points - creates the 'rose' command
    entry_points={
        "console_scripts": [
            "rose=integration.cli:main",
        ],
    },
    
    # Custom commands
    cmdclass={
        'develop': PostDevelopCommand,
        'install': PostInstallCommand,
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    
    # Keywords for PyPI
    keywords=[
        "security",
        "analysis",
        "cybersecurity",
        "ai",
        "sast",
        "secrets-detection",
        "vulnerability-scanner",
        "compliance",
        "aws",
        "bedrock",
        "athena",
    ],
    
    # Project URLs
    project_urls={
        "Bug Reports": "https://github.com/yourusername/rose-security-analyst/issues",
        "Source": "https://github.com/yourusername/rose-security-analyst",
        "Documentation": "https://github.com/yourusername/rose-security-analyst/blob/main/README.md",
    },
)
