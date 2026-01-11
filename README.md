# ROSe (Read-Only Security)

**An OSS-first AI cybersecurity analysis platform that inspects code, configurations, dependencies, and telemetry in strictly read-only mode.**

ROSe generates comprehensive risk reports, threat models, and governance insights without modifying systems, enforcing policies, or deploying infrastructure. It operates as an intelligent cybersecurity observatory that helps security architects, engineers, and analysts make informed decisions based on thorough analysis rather than automated enforcement.

## 🔍 What ROSe Does

ROSe provides **analysis-only cybersecurity intelligence** across multiple dimensions:

- **🔐 Security Pattern Analysis** - Detects security patterns, anti-patterns, and vulnerabilities in code
- **📋 SDD Compliance Validation** - Validates Spec-Driven Development artifacts and governance policies  
- **🛡️ Threat Intelligence** - Performs SAST scanning, secret detection, and threat modeling
- **📊 Data Governance Analysis** - Analyzes access patterns, data classification, and policy compliance
- **🔄 Shadow Mode Risk Assessment** - Evaluates proposed changes in isolated environments
- **📈 Reliability Intelligence** - Provides incident analysis and performance pattern insights
- **🎯 Dependency Security** - Scans dependencies and validates supply chain security

## 🚫 What ROSe Does NOT Do

ROSe operates under strict **read-only principles**:

- ❌ **No System Modification** - Never changes code, configurations, or infrastructure
- ❌ **No Policy Enforcement** - Only reports violations, never enforces policies
- ❌ **No Autonomous Remediation** - Provides recommendations, requires human approval
- ❌ **No Production Deployment** - Analysis only, no infrastructure provisioning
- ❌ **No Destructive Operations** - Cannot delete, modify, or break existing systems

## 🏗️ Architecture

ROSe uses a **multi-language, OSS-first architecture**:

```
┌─────────────────────────────────────────────────────────────┐
│                    ROSe Analysis Platform                   │
├─────────────────────────────────────────────────────────────┤
│  🐍 Python AI Analyst     │  🔧 Go Security Analyzer      │
│  • Ollama LLM Integration │  • Semgrep SAST Analysis      │
│  • SDD Compliance Engine  │  • Gitleaks Secret Detection  │
│  • Security Pattern AI    │  • Wazuh SIEM Integration     │
│                           │  • Falco Runtime Analysis     │
├─────────────────────────────────────────────────────────────┤
│  ⚡ C++ Performance       │  📊 Data Intelligence Layer   │
│  • OpenSSL Crypto Analysis│  • DuckDB Analytics Engine    │
│  • libsodium Validation   │  • MinIO S3-Compatible Store  │
│  • Performance Benchmarks │  • SOPS Encryption Analysis   │
├─────────────────────────────────────────────────────────────┤
│              🔗 Unified Integration Platform                │
│         Cross-component orchestration & reporting          │
└─────────────────────────────────────────────────────────────┘
```

### OSS-First Technology Stack

**Default OSS Stack (Zero Cost)**:
- **Ollama/llama.cpp** - Local AI model analysis
- **Wazuh + Falco** - Security event analysis and threat detection
- **DuckDB + MinIO** - High-performance analytics and S3-compatible storage
- **Prometheus + Grafana** - Metrics analysis and monitoring intelligence
- **Semgrep OSS** - Static application security analysis
- **Gitleaks** - Secret detection and analysis

**Optional AWS Upgrade Paths**:
- Clearly documented enterprise upgrade options
- Cost warnings and budget caps for all paid services
- Feature parity explanations between OSS and AWS options

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** with pip
- **Go 1.19+** 
- **C++ compiler** (GCC/Clang with C++17 support)
- **Docker & Docker Compose** (for OSS stack)

### Installation

1. **Clone ROSe**:
   ```bash
   git clone <repository-url>
   cd rose
   ```

2. **Set up the platform**:
   ```bash
   # Windows
   .\scripts\setup-platform.ps1
   
   # Linux/macOS  
   ./scripts/setup-platform.sh
   ```

3. **Start OSS analysis stack**:
   ```bash
   docker-compose up -d
   ```

4. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Basic Usage

**Analyze a repository**:
```bash
python -m src.python.integration.cli analyze-repo /path/to/repository
```

**Run security dashboard**:
```bash
python -m src.python.use_case_demo.demo_runner
```

**Generate comprehensive report**:
```bash
python -m src.python.integration.cli full-analysis /path/to/project
```

## 📁 Project Structure

```
rose/
├── src/
│   ├── python/           # AI Security Analyst & Integration
│   │   ├── ai_analyst/   # Ollama-powered security analysis
│   │   ├── data_intelligence/  # DuckDB analytics engine
│   │   ├── data_protection/    # Log redaction & data safety
│   │   ├── agentic_modules/    # Shadow mode & reliability
│   │   ├── integration/        # Unified platform & CLI
│   │   └── use_case_demo/      # Security dashboard demo
│   ├── go/               # Security Intelligence Analyzer
│   │   └── security_analyzer/  # Semgrep, Gitleaks, Wazuh integration
│   └── cpp/              # Performance Security Analyzer
│       └── performance_analyzer/  # OpenSSL, libsodium analysis
├── tests/
│   ├── unit/             # Property-based tests (28 properties)
│   └── integration/      # End-to-end workflow tests
├── data/
│   ├── analysis/         # Analysis results and context
│   └── synthetic/        # Synthetic data generation
├── scripts/              # Setup and automation scripts
├── docs/                 # Documentation and setup guides
└── .kiro/specs/          # Spec-driven development artifacts
```

## 🧪 Testing

ROSe includes comprehensive testing with **28 correctness properties**:

**Run all tests**:
```bash
# Python property-based tests
python -m pytest tests/unit/ -v

# Go security analyzer tests  
cd src/go/security_analyzer && go test -v

# C++ performance analyzer tests
cd src/cpp/performance_analyzer && make test
```

**Property-based testing** validates universal correctness properties:
- Repository context persistence
- SDD compliance validation  
- Security pattern detection
- Data protection and redaction
- Access pattern analysis
- Shadow mode risk assessment
- And 22 more critical properties...

## 🔧 Configuration

### OSS Stack Configuration

ROSe uses Docker Compose for the default OSS stack:

```yaml
# docker-compose.yml
services:
  ollama:          # Local LLM analysis
  wazuh:           # SIEM analysis  
  falco:           # Runtime security
  duckdb:          # Analytics engine
  minio:           # S3-compatible storage
  prometheus:      # Metrics collection
  grafana:         # Analysis dashboards
```

### Analysis Configuration

Configure analysis behavior in `config/oss/`:
- **Ollama models** - Choose local LLM models for analysis
- **Semgrep rules** - Customize SAST analysis rules
- **Data governance** - Set data classification policies
- **Shadow mode** - Configure risk assessment parameters

## 📊 Use Cases

### 1. Security Posture Assessment
```bash
python -m src.python.integration.cli security-assessment /path/to/codebase
```
- Comprehensive security pattern analysis
- Vulnerability detection and risk scoring
- Compliance gap identification
- Actionable remediation recommendations

### 2. SDD Governance Validation  
```bash
python -m src.python.integration.cli sdd-compliance /path/to/project
```
- Validates requirements.md, design.md, tasks.md
- Checks steering file policy compliance
- Generates governance compliance reports
- Identifies documentation gaps

### 3. Shadow Mode Risk Analysis
```bash
python -m src.python.agentic_modules.shadow_mode_analyzer analyze-change /path/to/changes
```
- Isolated risk assessment of proposed changes
- Impact analysis and blast radius calculation
- Rollback recommendations and safety checks
- Change readiness validation

### 4. Data Governance Intelligence
```bash
python -m src.python.data_intelligence.oss_data_intelligence analyze-governance /path/to/data
```
- Access pattern analysis and optimization
- Data classification and policy compliance
- Cross-account access pattern recommendations
- Policy conflict detection and resolution

## 🛡️ Security & Privacy

ROSe prioritizes security and privacy:

- **🔒 Read-Only Operations** - Never modifies target systems
- **🏠 Local-First Analysis** - OSS stack runs entirely locally
- **🔐 Automatic Secret Redaction** - PII and credentials automatically redacted
- **🎭 Synthetic Data Only** - All test data is synthetically generated
- **📝 Audit Trails** - Complete analysis audit logs maintained
- **🚫 No Data Exfiltration** - Analysis results stay in your environment

## 🤝 Contributing

ROSe follows **Spec-Driven Development (SDD)**:

1. **Requirements** - Define what needs to be built
2. **Design** - Specify how it will be built  
3. **Tasks** - Break down implementation steps
4. **Property-Based Testing** - Validate correctness properties

See `.kiro/specs/ai-cybersecurity-platform/` for complete specifications.

### Development Setup

```bash
# Set up git hooks for security
.\scripts\setup-git-hooks.ps1

# Generate synthetic test data
.\scripts\generate-synthetic-data.ps1

# Run comprehensive test suite
python -m pytest tests/ -v --tb=short
```

## 📄 License

ROSe is open-source software. See LICENSE file for details.

## 🆘 Support

- **Documentation**: `docs/setup/README.md`
- **Issues**: GitHub Issues
- **Discussions**: GitHub Discussions

---

**ROSe (Read-Only Security)** - *Intelligent cybersecurity analysis without the risk*