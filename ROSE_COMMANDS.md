# ROSe Command Reference

All commands work from the project root directory. No more complex module paths!

## ✅ Working Now (No AWS Setup Required)

### 📊 Security Analysis & Reports

```bash
# Analyze current directory
python rose.py analyze .

# Analyze specific path
python rose.py analyze /path/to/project

# Security scan with HTML report
python rose.py analyze . --types security --report --open

# Multiple analysis types
python rose.py analyze . --types security sast secrets compliance

# Comprehensive workflow
python rose.py workflow . --type comprehensive
```

**Analysis Types:**
- `security` - General security analysis
- `sast` - Static application security testing
- `secrets` - Find exposed credentials
- `compliance` - Compliance checking
- `crypto` - Cryptography analysis

**Workflow Types:**
- `comprehensive` - Full analysis
- `security` - Security-focused
- `compliance` - Compliance-focused
- `documentation` - Documentation-focused

### 🎬 Demo Features (Working Now!)

```bash
# Security insights generator (BEST FOR SCREENSHOTS!)
python rose.py demo insights

# Interactive onboarding tutorial
python rose.py demo onboarding
```

---

## 🔧 Requires AWS Setup

These features are implemented but need AWS Bedrock and infrastructure:

### 🤖 Interactive AI Security Analyst

```bash
# Start the interactive AI analyst CLI (requires AWS Bedrock)
python rose.py chat

# Alternative commands (all require AWS Bedrock)
python rose.py analyst
python rose.py ai
python rose.py ask
```

**What you can ask (once AWS is configured):**
- "Are we being attacked right now?"
- "What are our top 5 security risks?"
- "Show me compliance status for SOX"
- "Find suspicious login patterns"
- "What vulnerabilities do we have?"
- "Analyze failed authentication attempts"
- "Show me security trends this week"

### 🎬 AWS-Powered Demos

```bash
# Web dashboard (requires AWS infrastructure)
python rose.py demo web

# Cost optimization analysis (requires AWS cost tracking)
python rose.py demo cost

# Integration pipeline demo (requires AWS services)
python rose.py demo pipeline
```

### ☁️ AWS Management

```bash
# Deploy AWS infrastructure
python rose.py aws deploy

# Validate AWS setup
python rose.py aws validate
```

---

## 📋 Quick Start

1. **Install:**
   ```bash
   pip install -e .
   ```

2. **Chat with AI Analyst:**
   ```bash
   python rose.py chat
   ```

3. **Analyze your code:**
   ```bash
   python rose.py analyze . --types security --report --open
   ```

4. **Try the web dashboard:**
   ```bash
   python rose.py demo web
   ```

---

## 💡 Tips

- **All commands work from project root** - no need to cd into subdirectories
- **Use `python rose.py --help`** for full command list
- **The chat interface is the star** - showcase this in demos
- **Reports open automatically** with `--open` flag
- **Web dashboard runs on** http://localhost:8000

---

## 🎥 For Competition Demo

**Commands that work NOW (use these for screenshots!):**

1. **Security Insights** (BEST DEMO!):
   ```bash
   python rose.py demo insights
   ```
   Shows comprehensive security analysis with executive summaries, compliance reports, and action plans

2. **Interactive Onboarding**:
   ```bash
   python rose.py demo onboarding
   ```
   Demonstrates tutorials, sample data generation, and business value

3. **Security Report**:
   ```bash
   python rose.py analyze . --types security --report --open
   ```
   Generates professional HTML security report

**Commands requiring AWS setup (mention as "coming soon"):**
- `python rose.py chat` - AI conversational interface
- `python rose.py demo web` - Web dashboard
- `python rose.py demo cost` - Cost optimization

---

## 🚀 Competition Article Commands

**Use these exact commands in your article and screenshots:**

### ✅ Working Now (No AWS Required)

```bash
# Installation
pip install -e .

# Security Insights Demo (BEST FOR ARTICLE!)
python rose.py demo insights

# Interactive Onboarding
python rose.py demo onboarding

# Security analysis with report
python rose.py analyze . --types security --report --open

# Workflow analysis
python rose.py workflow . --type comprehensive
```

### 🔧 Coming Soon (Requires AWS Setup)

```bash
# AI Chat interface (requires AWS Bedrock)
python rose.py chat

# Web dashboard (requires AWS infrastructure)
python rose.py demo web

# Cost optimization (requires AWS cost tracking)
python rose.py demo cost
```

**Focus your article on the working features!** They're impressive and demonstrate real value without requiring AWS setup.

---

**No more `-m src.python.aws_bedrock_athena_ai.module` nonsense!**

Everything is simple and clean through `rose.py` 🎉
