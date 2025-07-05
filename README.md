# AI Code Scanner CLI

A powerful command-line tool for scanning code files and complete codebases using **Snyk CLI** for vulnerability detection and **Google's Gemini API** for enhanced analysis. This tool provides comprehensive security analysis with detailed remediation guidance, OWASP Top 10 mapping, and code snippets.

## Features

- 🔍 **Snyk-Powered Scanning**: Uses industry-standard Snyk CLI for accurate vulnerability detection
- 🤖 **AI-Enhanced Analysis**: Gemini API provides detailed explanations, remediation, and OWASP mapping
- 📊 **Rich Output Formats**: Table, JSON, and Markdown output with code snippets
- 🎯 **OWASP Top 10 Mapping**: Automatically maps vulnerabilities to OWASP categories
- 🔧 **Code Snippets**: Shows vulnerable code with context for better understanding
- 📁 **Professional Reports**: Detailed analysis with severity, description, and remediation
- 🚀 **Easy Installation**: Simple setup with built-in Snyk CLI installation

## Installation

### Prerequisites

- Python 3.8+
- Node.js and npm (for Snyk CLI)

### Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/ai-scanner-cli.git
cd ai-scanner-cli
```

2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

3. Install Snyk CLI (choose one method):

```bash
# Option 1: Use built-in installer
python main.py install-snyk

# Option 2: Manual installation
npm install -g snyk
```

4. Set up your API keys:

```bash
# Set Gemini API key
export GEMINI_API_KEY="your_gemini_api_key_here"

# Or create .env file
cp .env.example .env
# Edit .env and add your API key
```

5. Authenticate with Snyk:

```bash
snyk auth
```

## Usage

### Basic Usage

```bash
# Scan current directory
python main.py scan

# Scan specific directory
python main.py scan --path /path/to/your/project

# Test connections
python main.py test
```

### Advanced Usage

```bash
# High-severity issues only with JSON output
python main.py scan --severity high --format json --output security_report.json

# Scan with detailed output (includes code snippets)
python main.py scan --verbose --format markdown --output detailed_report.md

# Custom file patterns
python main.py scan --include "*.py,*.js,*.java" --exclude "test_*,*_test.py"
```

### Available Commands

#### `scan` - Perform security analysis

```bash
python main.py scan [OPTIONS]
```

**Options:**

- `--path, -p`: Path to file or directory to scan (default: current directory)
- `--api-key, -k`: Gemini API key (or set GEMINI_API_KEY env var)
- `--severity`: Minimum severity level: low, medium, high, critical (default: medium)
- `--format, -f`: Output format: json, table, markdown (default: table)
- `--output, -o`: Output file path (optional)
- `--verbose, -v`: Enable verbose output with code snippets
- `--max-files`: Maximum number of files to scan (default: 50)

#### `test` - Test API connections

```bash
python main.py test [--api-key YOUR_API_KEY]
```

#### `install-snyk` - Install Snyk CLI

```bash
python main.py install-snyk
```

#### `config` - Configure scanner settings

```bash
python main.py config [--set-api-key YOUR_API_KEY]
```

## How It Works

1. **Snyk Scanning**: The tool runs Snyk CLI to detect security vulnerabilities
2. **Code Analysis**: Extracts code snippets around vulnerable lines
3. **AI Enhancement**: Sends Snyk results to Gemini API for detailed analysis
4. **Report Generation**: Produces comprehensive reports with:
   - Detailed vulnerability descriptions
   - Specific remediation steps
   - OWASP Top 10 category mapping
   - Code snippets with context
   - Severity assessment

## Output Formats

### Table Format (Default)

```
┌─────────────┬──────┬──────────┬──────────────────────┬──────────────────────┬─────────────────────────┐
│ File        │ Line │ Severity │ OWASP                │ Issue                │ Description             │
├─────────────┼──────┼──────────┼──────────────────────┼──────────────────────┼─────────────────────────┤
│ app.js      │   31 │ HIGH     │ A03:2021 - Injection │ Command Injection    │ Unsanitized input flows│
│ app.js      │   21 │ HIGH     │ A03:2021 - Injection │ SQL Injection        │ User input in SQL query │
└─────────────┴──────┴──────────┴──────────────────────┴──────────────────────┴─────────────────────────┘
```

### JSON Format

```json
{
  "summary": {
    "total_issues": 5,
    "by_severity": {
      "high": 3,
      "medium": 2
    },
    "by_owasp": {
      "A03:2021 - Injection": 3,
      "A07:2021 - Identification and Authentication Failures": 2
    }
  },
  "issues": [
    {
      "file_path": "app.js",
      "line_number": 31,
      "severity": "high",
      "title": "Command Injection Vulnerability",
      "description": "Unsanitized input flows into child_process.exec...",
      "recommendation": "Use parameterized commands or input validation...",
      "owasp_category": "A03:2021 - Injection",
      "code_snippet": "29    app.post('/execute', (req, res) => {\n30        const command = req.body.command;\n31 ->     exec(command, (error, stdout, stderr) => {\n32            if (error) {\n33                res.status(500).send(error.message);"
    }
  ]
}
```

### Markdown Format

```markdown
# AI Code Security Scan Results

## Summary

- **Total Issues**: 5
- **High Severity**: 3
- **Medium Severity**: 2

## Issues by OWASP Category

- **A03:2021 - Injection**: 3
- **A07:2021 - Identification and Authentication Failures**: 2

### 1. Command Injection Vulnerability

- **File**: `app.js`
- **Line**: 31
- **Severity**: **HIGH**
- **OWASP Category**: A03:2021 - Injection

**Description**: Unsanitized input from HTTP parameter flows into child_process.exec...

**Remediation**: Use parameterized commands, input validation, or safer alternatives...

**Code Snippet**:
```

29 app.post('/execute', (req, res) => {
30 const command = req.body.command;
31 -> exec(command, (error, stdout, stderr) => {
32 if (error) {
33 res.status(500).send(error.message);

```

```

## Example Scan Results

Based on the Snyk output you provided, here's what the enhanced tool would produce:

```bash
python main.py scan --path /path/to/vulnerable_app --verbose
```

**Output:**

````
📊 Scan Summary
• Files Scanned: 1
• Total Issues: 6
• Files with Issues: 1
• Duration: 15.3 seconds

📈 Issues by Severity
• High: 4
• Medium: 2

🛡️ Issues by OWASP Category
• A03:2021 - Injection: 2
• A07:2021 - Cross-Site Scripting (XSS): 2
• A06:2021 - Vulnerable Components: 1
• A04:2021 - Insecure Design: 1

┌─────────────┬──────┬──────────┬──────────────────────┬──────────────────────┬─────────────────────────┐
│ File        │ Line │ Severity │ OWASP                │ Issue                │ Description             │
├─────────────┼──────┼──────────┼──────────────────────┼──────────────────────┼─────────────────────────┤
│ app.js      │   31 │ HIGH     │ A03:2021 - Injection │ Command Injection    │ Unsanitized input flows│
│ app.js      │   21 │ HIGH     │ A03:2021 - Injection │ SQL Injection        │ User input in SQL query │
│ app.js      │   14 │ HIGH     │ A07:2021 - XSS       │ Cross-site Scripting │ Unsanitized input in... │
│ app.js      │   38 │ HIGH     │ A07:2021 - XSS       │ Cross-site Scripting │ File upload XSS risk    │
│ app.js      │   29 │ MEDIUM   │ A04:2021 - Insecure  │ Resource Allocation  │ No rate limiting on...  │
│ app.js      │    5 │ MEDIUM   │ A06:2021 - Vulnerable│ Information Exposure │ X-Powered-By header...  │
└─────────────┴──────┴──────────┴──────────────────────┴──────────────────────┴─────────────────────────┘

================================================================================
Detailed Issue Analysis with Code Snippets
================================================================================

Issue #1
Title: Command Injection Vulnerability
File: app.js
Line: 31
Severity: HIGH
Type: Command Injection
OWASP Category: A03:2021 - Injection
Confidence: 0.95

Description: Unsanitized user input from HTTP request body flows directly into child_process.exec() function, allowing attackers to execute arbitrary system commands on the server.

Code Snippet:
┌─ Vulnerable Code ─┐
│ 29    app.post('/execute', (req, res) => {    │
│ 30        const command = req.body.command;   │
│ 31 ->     exec(command, (error, stdout, stderr) => { │
│ 32            if (error) {                    │
│ 33                res.status(500).send(error.message); │
└─────────────────────────────────────────────────────┘

Remediation:
1. Use parameterized commands or command whitelisting
2. Implement strict input validation and sanitization
3. Consider using safer alternatives like spawn() with argument arrays
4. Apply the principle of least privilege for system commands

Example fix:
```javascript
const allowedCommands = ['ls', 'date', 'whoami'];
if (allowedCommands.includes(command)) {
    exec(command, callback);
} else {
    res.status(400).send('Command not allowed');
}
````

````

## API Key Setup

### Get Gemini API Key
1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Set the environment variable:
   ```bash
   export GEMINI_API_KEY="your_api_key_here"
````

### Setup Snyk Account

1. Sign up at [Snyk.io](https://snyk.io)
2. Run `snyk auth` to authenticate
3. (Optional) Configure organization settings

## Troubleshooting

### Common Issues

1. **Snyk CLI not found**: Install with `npm install -g snyk` or use `python main.py install-snyk`
2. **Gemini API errors**: Check your API key and rate limits
3. **No issues found**: Ensure your code has detectable vulnerabilities or adjust severity level
4. **Permission denied**: Ensure you have read permissions for the target directory

### Debug Mode

Use `--verbose` flag to see:

- Detailed issue analysis
- Code snippets with context
- Processing steps
- API response details

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:

- Create an issue on GitHub
- Check the troubleshooting section
- Review the examples for common use cases
