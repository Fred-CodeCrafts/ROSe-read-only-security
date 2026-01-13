"""
Setup script for AI Security Analyst in Your Pocket
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), 'README.md')
    if os.path.exists(readme_path):
        with open(readme_path, 'r', encoding='utf-8') as f:
            return f.read()
    return "AI Security Analyst in Your Pocket - AWS Bedrock + Athena Integration"

# Read requirements
def read_requirements():
    requirements_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_path):
        with open(requirements_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return []

setup(
    name="aws-bedrock-athena-ai",
    version="0.1.0",
    author="AI Security Analyst Team",
    author_email="team@aisecurityanalyst.com",
    description="AI Security Analyst combining AWS Bedrock reasoning with Athena data querying",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/aws-bedrock-athena-ai",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.11.0",
            "moto>=4.2.0",
            "hypothesis>=6.82.0",
            "black>=23.7.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
            "isort>=5.12.0",
        ],
        "ml": [
            "scikit-learn>=1.3.0",
            "matplotlib>=3.7.0",
            "seaborn>=0.12.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "ai-security-analyst=aws_bedrock_athena_ai.cli:main",
            "deploy-infrastructure=aws_bedrock_athena_ai.infrastructure.deploy_infrastructure:main",
        ],
    },
    include_package_data=True,
    package_data={
        "aws_bedrock_athena_ai": [
            "infrastructure/*.yaml",
            "config/*.yaml",
            "templates/*.sql",
        ],
    },
)