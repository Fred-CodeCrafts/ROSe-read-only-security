# ROSe (Read-Only Security) Setup Guide

## Overview

This guide helps you set up **ROSe (Read-Only Security)** - an OSS-first AI cybersecurity analysis platform that provides deep security insights without autonomous remediation.

## 🎯 Quick Start (5 Minutes)

### Prerequisites

- **Docker & Docker Compose** (for OSS stack)
- **Python 3.8+** (for AI analysis components)
- **Go 1.19+** (for security analyzer)
- **Git** (with hooks support)

### 1. Clone and Setup

```bash
# Clone the repository
git clone <repository-url>
cd rose

# Setup Git hooks for security
./scripts/setup-git-hooks.ps1

# Generate synthetic data
./scripts/generate-synthetic-data.ps1
```

### 2. Start OSS Stack

```bash
# Start all OSS services
docker-compose up -d

# Verify services are running
docker-compose ps
```

### 3. Access Services

- **Grafana Dashboard**: http://localhost:3000 (admin/admin123)
- **Prometheus Metrics**: http://localhost:9090
- **MinIO Console**: http://localhost:9001 (minioadmin/minioadmin123)
- **Ollama API**: http://localhost:11434

## 🏗️ Architecture Overview

### OSS-First Design

The platform uses **100% open-source tools** by default with optional AWS upgrade paths:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   AI Analysis   │    │ Security Intel  │    │ Performance     │
│   (Python)      │    │ (Go)           │    │ (C++)          │
│                 │    │                │    │                │
│ • Ollama        │    │ • Wazuh        │    │ • OpenSSL      │
│ • LangChain     │    │ • Falco        │    │ • libsodium    │
│ • ChromaDB      │    │ • Semgrep      │    │ • Local Crypto │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
         ┌─────────────────────────────────────────────────┐
         │              Data & Analytics                   │
         │                                                 │
         │ • DuckDB (Analytics)  • MinIO (Storage)        │
         │ • Prometheus (Metrics) • Grafana (Dashboards)  │
         │ • SQLite (State)      • SOPS (Secrets)         │
         └─────────────────────────────────────────────────┘
```

### Cost Structure

- **Default**: $0/month (100% OSS)
- **AWS Upgrade**: Optional, clearly documented costs
- **No Hidden Fees**: All costs transparent and opt-in

## 📋 Detailed Setup

### Step 1: Environment Preparation

#### Install Dependencies

**Windows (PowerShell):**
```powershell
# Install Docker Desktop
winget install Docker.DockerDesktop

# Install Python
winget install Python.Python.3.11

# Install Go
winget install GoLang.Go

# Install Git
winget install Git.Git
```

**Linux (Ubuntu/Debian):**
```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh

# Install Python
sudo apt update
sudo apt install python3 python3-pip

# Install Go
sudo apt install golang-go

# Install Git
sudo apt install git
```

#### Verify Installation

```bash
docker --version          # Should be 20.10+
docker-compose --version  # Should be 2.0+
python --version          # Should be 3.8+
go version                # Should be 1.19+
git --version             # Should be 2.30+
```

### Step 2: Security Configuration

#### Setup Git Hooks

```bash
# Configure Git hooks for secret detection
./scripts/setup-git-hooks.ps1

# Test the setup (should block commits with secrets)
echo "api_key = 'AKIA1234567890123456'" > test_secret.txt
git add test_secret.txt
git commit -m "test"  # Should be blocked
rm test_secret.txt
```

#### Install Gitleaks (Secret Detection)

**Windows:**
```powershell
winget install gitleaks
```

**Linux:**
```bash
# Download and install gitleaks
curl -sSfL https://github.com/zricethezav/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz | tar -xz
sudo mv gitleaks /usr/local/bin/
```

### Step 3: OSS Stack Deployment

#### Start Core Services

```bash
# Start all OSS services in background
docker-compose up -d

# Check service health
docker-compose ps
docker-compose logs --tail=50
```

#### Verify Service Health

```bash
# Test Ollama (AI Analysis)
curl http://localhost:11434/api/version

# Test Prometheus (Metrics)
curl http://localhost:9090/-/healthy

# Test MinIO (Storage)
curl http://localhost:9000/minio/health/live

# Test Grafana (Dashboards)
curl http://localhost:3000/api/health
```

### Step 4: Data Preparation

#### Generate Synthetic Data

```bash
# Install Python dependencies
pip install -r requirements.txt

# Generate synthetic datasets
./scripts/generate-synthetic-data.ps1

# Verify data generation
ls -la data/synthetic/
```

#### Load Initial Data

```bash
# Load synthetic data into DuckDB
python scripts/load-initial-data.py

# Verify data loading
docker-compose exec duckdb duckdb /data/security_analysis.db -c "SHOW TABLES;"
```

### Step 5: Component Testing

#### Test AI Analysis Component

```bash
cd src/python/ai_analyst
python -m pytest tests/ -v
```

#### Test Security Analyzer

```bash
cd src/go/security_analyzer
go test ./... -v
```

#### Test Performance Analyzer

```bash
cd src/cpp/performance_analyzer
mkdir build && cd build
cmake .. && make
./tests/run_tests
```

## 🔧 Configuration

### Environment Variables

Create `.env` file (never commit this):

```bash
# OSS Configuration
OLLAMA_HOST=http://localhost:11434
WAZUH_API_URL=http://localhost:55000
PROMETHEUS_URL=http://localhost:9090
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin123

# Analysis Configuration
ANALYSIS_DB_PATH=./data/analysis/security_analysis.db
SYNTHETIC_DATA_PATH=./data/synthetic/
LOG_LEVEL=INFO

# Security Configuration
ENABLE_SECRET_DETECTION=true
ENABLE_PII_REDACTION=true
SYNTHETIC_DATA_ONLY=true
```

### Service Configuration

#### Ollama Models

```bash
# Pull recommended models for security analysis
docker-compose exec ollama ollama pull llama2:7b
docker-compose exec ollama ollama pull codellama:7b
docker-compose exec ollama ollama pull mistral:7b
```

#### Wazuh Rules

```bash
# Copy custom security rules
cp config/oss/wazuh/custom_rules.xml /var/ossec/etc/rules/
docker-compose restart wazuh-manager
```

#### Grafana Dashboards

```bash
# Import cybersecurity dashboards
cp config/oss/grafana/dashboards/*.json /var/lib/grafana/dashboards/
docker-compose restart grafana
```

## 🧪 Testing the Setup

### End-to-End Test

```bash
# Run comprehensive system test
python scripts/test-system-health.py

# Expected output:
# ✅ All OSS services healthy
# ✅ AI analysis components ready
# ✅ Security analyzers operational
# ✅ Synthetic data loaded
# ✅ Dashboards accessible
```

### Security Test

```bash
# Test secret detection
echo "password = 'super_secret_123'" > test_file.py
git add test_file.py
git commit -m "test"  # Should be blocked by pre-commit hook

# Test synthetic data validation
python -c "
from data.synthetic.generator import CybersecurityDataGenerator
gen = CybersecurityDataGenerator()
data = gen.generate_synthetic_users(10)
print('✅ Synthetic data validation passed' if gen.validate_synthetic_data(data) else '❌ Validation failed')
"
```

## 🚀 Next Steps

1. **Explore Dashboards**: Visit http://localhost:3000 to see security analytics
2. **Run Analysis**: Execute your first security analysis workflow
3. **Review Documentation**: Check `docs/` for detailed component guides
4. **Customize Rules**: Modify analysis rules in `config/oss/`
5. **Scale Up**: Consider AWS upgrade paths for enterprise features

## 🆘 Troubleshooting

### Common Issues

**Docker Services Won't Start:**
```bash
# Check Docker daemon
docker info

# Check port conflicts
netstat -tulpn | grep -E ':(3000|9090|11434|55000)'

# Reset Docker state
docker-compose down -v
docker system prune -f
docker-compose up -d
```

**Python Dependencies Issues:**
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

**Git Hooks Not Working:**
```bash
# Verify hooks path
git config core.hooksPath

# Re-run setup
./scripts/setup-git-hooks.ps1

# Test manually
.githooks/pre-commit.ps1
```

### Getting Help

- **Documentation**: Check `docs/` directory
- **Logs**: `docker-compose logs <service-name>`
- **Health Checks**: `python scripts/test-system-health.py`
- **Issues**: Create GitHub issue with logs and system info

## 🔒 Security Notes

- All data is synthetic and safe for development
- Pre-commit hooks prevent accidental secret commits
- OSS stack runs locally with no external data transmission
- AWS upgrade paths are optional and clearly documented
- Regular security updates recommended for all components