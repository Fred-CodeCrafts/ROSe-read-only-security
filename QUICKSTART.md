# ROSe Quick Start Guide

## 🎯 Get ROSe Running in 5 Minutes (No AWS Required!)

ROSe runs **100% locally** using open-source tools. No cloud accounts needed!

### Step 1: Prerequisites
```bash
# Check if you have the basics
docker --version          # Need Docker Desktop
python --version          # Need Python 3.8+
git --version             # Need Git
```

### Step 2: Setup ROSe
```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Set up security hooks (prevents accidental secret commits)
.\scripts\setup-git-hooks.ps1

# 3. Generate synthetic test data
.\scripts\generate-synthetic-data.ps1

# 4. Start the OSS analysis stack (optional - for full features)
docker-compose up -d
```

### Step 3: Run Your First Analysis

**Option A: Quick Demo (No Docker needed)**
```bash
# Run the security dashboard demo
python -m src.python.use_case_demo.demo_runner

# This will show you:
# - Security pattern analysis
# - Mock threat scenarios
# - Risk assessments
# - Compliance reports
```

**Option B: Analyze Your Own Code**
```bash
# Analyze any repository
python -m src.python.integration.cli analyze-repo C:\path\to\your\project

# This will generate:
# - Security analysis report
# - Compliance assessment
# - Vulnerability findings
# - Recommendations
```

**Option C: Interactive Security Analysis**
```bash
# Start the interactive CLI
python -m src.python.integration.cli

# Then use commands like:
# > analyze-security /path/to/code
# > check-compliance /path/to/project
# > generate-report /path/to/output
```

### Step 4: View Results

**Security Dashboard (if Docker is running):**
- Visit http://localhost:3000 (Grafana)
- Username: admin, Password: admin123

**Command Line Results:**
- Reports saved to `data/analysis/reports/`
- View with any text editor or browser

### Step 5: Explore Features

**Security Pattern Analysis:**
```bash
python -m src.python.ai_analyst.oss_security_analyst analyze-patterns /path/to/code
```

**SDD Compliance Check:**
```bash
python -m src.python.ai_analyst.oss_security_analyst check-sdd /path/to/project
```

**Dependency Security Scan:**
```bash
python -m src.python.agentic_modules.dependency_analyzer scan /path/to/requirements.txt
```

**Shadow Mode Risk Assessment:**
```bash
python -m src.python.agentic_modules.shadow_mode_analyzer assess-change /path/to/changes
```

## 🔧 What Each Component Does

### 1. AI Security Analyst (Python)
- **What it does**: Analyzes code for security patterns using local AI
- **How to use**: `python -m src.python.ai_analyst.oss_security_analyst`
- **Output**: Security reports, compliance assessments, fix recommendations

### 2. Security Intelligence (Go)
- **What it does**: SAST scanning, secret detection, threat analysis
- **How to use**: `go run src/go/security_analyzer/main.go`
- **Output**: Vulnerability reports, secret detection alerts

### 3. Performance Analyzer (C++)
- **What it does**: Cryptographic analysis, performance security assessment
- **How to use**: `src/cpp/performance_analyzer/main.exe`
- **Output**: Crypto usage reports, performance security metrics

### 4. Integration Platform (Python)
- **What it does**: Unified interface, cross-component orchestration
- **How to use**: `python -m src.python.integration.cli`
- **Output**: Comprehensive analysis reports, dashboards

## 📊 Example Workflows

### Workflow 1: Analyze a New Project (No AWS Needed!)
```bash
# 1. Clone or navigate to project
cd /path/to/your/project

# 2. Run comprehensive analysis (100% local)
python -m src.python.integration.cli analyze . --types security sast secrets

# 3. View results
# - Check data/analysis/reports/ for detailed reports
# - Open http://localhost:3000 for dashboard (if Docker running)
# - All analysis happens on your machine using Ollama + Wazuh
```

### Workflow 2: Security Code Review (OSS-Powered)
```bash
# 1. Analyze specific files using local AI
python -m src.python.ai_analyst.oss_security_analyst analyze-patterns ./src/

# 2. Check for secrets using Gitleaks (local)
python -m src.python.data_protection.log_redactor scan-secrets ./

# 3. Generate recommendations using Ollama (local LLM)
python -m src.python.integration.cli generate-recommendations ./analysis-results.json
```

### Workflow 3: Compliance Assessment (No Cloud Required)
```bash
# 1. Check SDD compliance using local rules
python -m src.python.ai_analyst.oss_security_analyst check-sdd .

# 2. Validate governance using local policies
python -m src.python.integration.governance_validator validate .

# 3. Generate compliance report (stored locally)
python -m src.python.integration.cli compliance-report .
```

### Workflow 4: Interactive Security Dashboard
```bash
# 1. Start the comprehensive demo (showcases all features)
python -m src.python.use_case_demo.demo_runner

# This demonstrates:
# - Real-time threat analysis using Wazuh
# - AI-powered security insights via Ollama
# - Interactive dashboards via Grafana
# - All running locally on your machine!
```

### Workflow 5: Continuous Security Monitoring
```bash
# 1. Set up git hooks for automatic scanning
.\scripts\setup-git-hooks.ps1

# 2. Start continuous monitoring stack
docker-compose up -d

# 3. Every commit now gets:
# - Secret detection (Gitleaks)
# - Security analysis (Semgrep OSS)
# - Compliance checks (local rules)
# - All without any cloud services!
```

## 🛠️ Troubleshooting

**"Module not found" errors:**
```bash
# Make sure you're in the project root and have installed dependencies
pip install -r requirements.txt
export PYTHONPATH="${PYTHONPATH}:$(pwd)"  # Linux/Mac
set PYTHONPATH=%PYTHONPATH%;%CD%          # Windows
```

**Docker services won't start:**
```bash
# ROSe works without Docker! Just skip the docker-compose step
# You'll still get all the core analysis features
```

**Permission errors:**
```bash
# On Windows, run PowerShell as Administrator
# On Linux/Mac, you might need sudo for Docker commands
```

## 🔍 About AWS: It's Optional, Not Required!

**You asked about AWS - here's the complete picture:**

### ROSe is OSS-First (Open Source Software First)
ROSe runs **100% locally** by default using open-source tools. **No AWS account needed!**

**Default OSS Stack (Zero Cost):**
- **Ollama** - Local AI analysis (replaces AWS Bedrock)
- **Wazuh + Falco** - Security monitoring (replaces AWS GuardDuty)
- **DuckDB + MinIO** - Analytics & storage (replaces AWS Athena + S3)
- **Prometheus + Grafana** - Metrics & dashboards (replaces AWS CloudWatch)
- **Semgrep OSS** - Code analysis (replaces AWS CodeGuru)

### AWS is Only for Enterprise Upgrades
AWS services are **optional upgrade paths** for enterprise scale:

| Feature | OSS Default (FREE) | AWS Upgrade (PAID) | When to Upgrade |
|---------|-------------------|-------------------|-----------------|
| **AI Analysis** | Ollama (local LLM) | AWS Bedrock | Need enterprise SLA + compliance |
| **Security Monitoring** | Wazuh + Falco | AWS GuardDuty | Need managed threat intel feeds |
| **Data Analytics** | DuckDB + MinIO | AWS Athena + S3 | Need petabyte-scale analysis |
| **Metrics & Dashboards** | Prometheus + Grafana | AWS CloudWatch | Need cross-account monitoring |
| **Code Analysis** | Semgrep OSS | AWS CodeGuru | Need managed code insights |
| **Secret Detection** | Gitleaks | AWS Secrets Manager | Need enterprise secret rotation |

```bash
# OSS DEFAULT (FREE): Local Ollama analysis
python -m src.python.ai_analyst.oss_security_analyst analyze ./src

# AWS UPGRADE (PAID): Bedrock for enterprise scale
# Only if you need: managed scaling + compliance + enterprise SLA
# Cost risk: Token-based billing, no free tier
```

**When you might want AWS upgrades:**
- **Scale**: Analyzing thousands of repositories daily
- **Compliance**: Need SOC2/FedRAMP certified analysis
- **SLA**: Need 99.9% uptime guarantees
- **Integration**: Already using AWS for everything else

**When to stick with OSS (most users):**
- **Learning**: Exploring cybersecurity analysis
- **Small teams**: Under 50 repositories
- **Budget conscious**: Want $0 monthly costs
- **Privacy**: Keep all analysis local

### How to Use ROSe Without AWS

**Complete local setup:**
```bash
# 1. No AWS credentials needed!
# 2. Everything runs on your machine
docker-compose up -d  # Starts local OSS stack

# 3. Run analysis
python -m src.python.use_case_demo.demo_runner
# This gives you:
# - AI-powered security analysis (via Ollama)
# - Threat detection (via Wazuh/Falco)
# - Compliance reports (via local rules)
# - Interactive dashboards (via Grafana)
```

**What you get locally:**
- Full security analysis capabilities
- Interactive security dashboard
- Compliance assessment reports
- Threat pattern detection
- Risk scoring and recommendations
- All without any cloud dependencies!

## 🎉 You're Ready!

ROSe is now analyzing your code and generating security insights. The beauty of ROSe is that it's **read-only** - it will never modify your code or systems, just provide intelligent analysis and recommendations.

**Your ROSe runs locally by default - no AWS required!**

**Next Steps:**
- Explore the generated reports
- Try different analysis commands
- Set up the full Docker stack for advanced features
- Check out the comprehensive documentation in `docs/`
- Consider AWS upgrades only if you need enterprise scale