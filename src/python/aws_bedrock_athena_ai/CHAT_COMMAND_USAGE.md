# Chat Command Usage Guide

## Overview
The ROSe AI Security Analyst now includes an interactive chat interface that allows you to ask security questions and receive detailed analysis.

## Starting the Chat Interface

You can start the chat interface using any of these commands:

```bash
python rose.py chat
python rose.py analyst
python rose.py ai
python rose.py ask
```

## Demo Mode vs Production Mode

### Demo Mode (Default)
When AWS Bedrock is not configured, the chat interface automatically runs in demo mode:
- ⚠️ Shows "Running in DEMO MODE" message
- 💡 Provides simulated responses for testing
- 🤖 Uses pre-built response templates
- ✅ Works without any AWS configuration

### Production Mode
When AWS Bedrock is configured:
- 🤖 Shows "Connected to AWS Bedrock" message
- ☁️ Uses real AWS Bedrock AI models
- 📊 Queries actual security data from Athena
- 🔒 Requires AWS credentials and permissions

## Available Commands

While in the chat interface, you can use these commands:

- **Type your question** - Ask any security-related question
- **`help`** - Show example questions
- **`exit`** or **`quit`** - End the chat session

## Example Session

```
╔══════════════════════════════════════════════════════════════╗
║     ROSe AI Security Analyst - Interactive Chat             ║
╚══════════════════════════════════════════════════════════════╝

⚠️  AWS Bedrock not configured - Running in DEMO MODE
💡 Demo mode provides simulated responses for testing

🤖 Demo Mode Active - Ask me about security!

Commands:
  • Type your security question and press Enter
  • Type 'exit' or 'quit' to end the session
  • Type 'help' for example questions

💬 You: What are our top security risks?

🤔 Analyzing...

🤖 ROSe: Based on analysis of your security posture, we've identified 3 high-priority risks:

1. **Unauthorized Access Attempts**: 47 failed login attempts detected from suspicious IPs
2. **Unpatched Systems**: 12 systems running outdated software with known vulnerabilities
3. **Data Exposure**: 2 S3 buckets with overly permissive access policies

These risks require immediate attention to prevent potential security incidents.

📊 Key Findings:
  • failed_logins: {'count': 47, 'unique_ips': 8, 'top_targeted_accounts': ['admin', 'root', 'service-account'], ...}
  • unpatched_systems: {'count': 12, 'critical_cves': ['CVE-2024-1234', 'CVE-2024-5678'], ...}
  • exposed_buckets: {'count': 2, 'bucket_names': ['logs-backup', 'temp-data'], ...}

💬 You: help

📚 Example Questions:
  • What are our top security risks?
  • Show me recent failed login attempts
  • Are there any suspicious network connections?
  • What security events happened in the last 24 hours?
  • Analyze authentication failures

💬 You: exit

👋 Thanks for using ROSe AI Security Analyst!
```

## Example Questions

Here are some questions you can ask:

### General Security
- "What are our top security risks?"
- "Give me a security overview"
- "What should I be worried about?"

### Authentication & Access
- "Show me recent failed login attempts"
- "Are there any unauthorized access attempts?"
- "Analyze authentication failures"

### Infrastructure
- "Are there any unpatched systems?"
- "What vulnerabilities do we have?"
- "Show me systems that need updates"

### Data Security
- "Are any S3 buckets publicly accessible?"
- "Check for data exposure risks"
- "Audit S3 permissions"

### Network Security
- "Are there any suspicious network connections?"
- "Show me unusual traffic patterns"
- "Check for network anomalies"

## Response Format

Each response includes:

1. **Executive Summary**: High-level overview of findings
2. **Key Findings**: Detailed technical information
3. **Recommendations**: Actionable steps to address issues (in detailed responses)

## Error Handling

The chat interface handles errors gracefully:

- **AWS Unavailable**: Automatically switches to demo mode
- **Import Errors**: Shows helpful installation instructions
- **Network Issues**: Retries or falls back to demo mode
- **Invalid Input**: Prompts for valid input

## Troubleshooting

### Chat Command Not Found
```bash
# Make sure you're in the project root directory
cd /path/to/ai-cybersecurity-project

# Try running with full path
python rose.py chat
```

### Import Errors
```bash
# Install dependencies
pip install -r requirements.txt

# Install package in development mode
pip install -e .
```

### AWS Configuration (Optional)
To use production mode with real AWS Bedrock:

1. Configure AWS credentials:
   ```bash
   aws configure
   ```

2. Ensure you have Bedrock access:
   ```bash
   aws bedrock list-foundation-models
   ```

3. Restart the chat interface

## Tips

1. **Start with demo mode** - Test the interface without AWS setup
2. **Use the help command** - See example questions anytime
3. **Ask follow-up questions** - Each session maintains context
4. **Be specific** - More specific questions get better answers
5. **Use natural language** - No need for special syntax

## Integration with Other Features

The chat interface integrates with:
- **Web Dashboard**: Same backend as `python rose.py demo web`
- **Demo Responses**: Consistent response format across interfaces
- **AWS Detector**: Automatic mode detection
- **Cost Optimization**: Can query cost-related information

## Next Steps

After trying the chat interface:

1. **Try the web dashboard**: `python rose.py demo web`
2. **Explore other demos**: `python rose.py demo insights`
3. **Configure AWS** (optional): For production mode
4. **Read the docs**: See ROSE_COMMANDS.md for more features

## Support

If you encounter issues:

1. Check the error message for specific guidance
2. Verify dependencies are installed
3. Try demo mode first (no AWS required)
4. Check logs for detailed error information

---

**Ready to try it?**

```bash
python rose.py chat
```

Ask: "What are our top security risks?"
