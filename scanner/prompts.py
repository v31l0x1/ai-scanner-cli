"""
Prompt templates for different types of code analysis
"""

def get_enhanced_analysis_prompt(snyk_issue: dict, code_snippet: str) -> str:
    """Generate enhanced analysis prompt for security issue using Gemini"""
    
    return f"""
You are an expert cybersecurity analyst and senior developer. I have a security issue detected by our code analysis tool that needs comprehensive analysis and detailed remediation guidance.

DETECTED ISSUE DETAILS:
- Issue Type: {snyk_issue.get('issue_type', snyk_issue.get('message', 'Unknown'))}
- Severity: {snyk_issue.get('severity', 'medium')}
- File: {snyk_issue.get('file_path', 'Unknown')}
- Line: {snyk_issue.get('line_number', 1)}
- Description: {snyk_issue.get('description', 'No description')}

CODE SNIPPET:
```
{code_snippet}
```

Please provide enhanced analysis in the following EXACT format:

TITLE: [Provide a clear, specific title for this vulnerability]
SEVERITY: [critical/high/medium/low - reassess based on exploitability and impact]
TYPE: [Specific vulnerability type]
DESCRIPTION: [Detailed technical explanation of the vulnerability, including why it occurs, attack vectors, and potential business impact]
REMEDIATION: [Comprehensive fix with multiple approaches: 1) Immediate fix with code example, 2) Best practices to prevent similar issues, 3) Additional security measures. Include specific code snippets showing before/after examples when possible]
OWASP: [Map to OWASP Top 10 2021 category with full identifier like "A03:2021 - Injection"]
CONFIDENCE: [0.0-1.0 confidence score for this assessment]

REMEDIATION REQUIREMENTS:
- Provide at least 3 specific remediation steps
- Include working code examples for fixes
- Explain WHY each step prevents the vulnerability
- Suggest additional security measures beyond the immediate fix
- Reference relevant security libraries or frameworks
- Include validation and testing approaches

IMPORTANT: 
- Each field must start on a new line with the field name followed by a colon
- Provide specific OWASP Top 10 2021 categories (A01, A02, A03, etc.)
- Make remediation section comprehensive and actionable
- Focus on practical implementation details

Be precise, technical, and provide implementable solutions.
"""

def get_scan_prompt(file_path: str, content: str, scan_type: str) -> str:
    """Generate appropriate prompt based on scan type"""
    
    base_prompt = f"""
You are an expert code security and quality analyst. Analyze the following code file and identify potential issues.

File: {file_path}

Code:
```
{content}
```

Please analyze this code for the following types of issues based on the scan type '{scan_type}':
"""
    
    if scan_type == 'security':
        return base_prompt + get_security_prompt()
    elif scan_type == 'quality':
        return base_prompt + get_quality_prompt()
    elif scan_type == 'performance':
        return base_prompt + get_performance_prompt()
    else:  # 'all'
        return base_prompt + get_comprehensive_prompt()

def get_security_prompt() -> str:
    """Get security-focused analysis prompt"""
    return """
SECURITY ANALYSIS - Look for:
1. SQL injection vulnerabilities
2. Cross-site scripting (XSS) vulnerabilities
3. Authentication and authorization issues
4. Input validation problems
5. Insecure cryptographic practices
6. Hardcoded secrets or credentials
7. Path traversal vulnerabilities
8. Command injection risks
9. Insecure deserialization
10. Missing security headers
11. Weak random number generation
12. Insecure file operations
13. Memory safety issues
14. Race conditions
15. Privilege escalation risks

For each issue found, provide:
ISSUE: [Brief title]
SEVERITY: [critical/high/medium/low]
TYPE: [security vulnerability type]
LINE: [line number where issue occurs]
DESCRIPTION: [Detailed explanation of the security issue]
RECOMMENDATION: [How to fix the issue]
CONFIDENCE: [0.0-1.0 confidence score]

Focus on real security vulnerabilities that could be exploited by attackers.
"""

def get_quality_prompt() -> str:
    """Get code quality analysis prompt"""
    return """
CODE QUALITY ANALYSIS - Look for:
1. Code complexity issues
2. Duplicate code blocks
3. Inconsistent naming conventions
4. Missing error handling
5. Poor function/class design
6. Unused variables or imports
7. Magic numbers/strings
8. Inconsistent formatting
9. Missing documentation
10. Violation of SOLID principles
11. Anti-patterns
12. Code smells
13. Maintainability issues
14. Readability problems
15. Testing gaps

For each issue found, provide:
ISSUE: [Brief title]
SEVERITY: [critical/high/medium/low]
TYPE: [code quality issue type]
LINE: [line number where issue occurs]
DESCRIPTION: [Detailed explanation of the quality issue]
RECOMMENDATION: [How to improve the code]
CONFIDENCE: [0.0-1.0 confidence score]

Focus on issues that affect code maintainability, readability, and best practices.
"""

def get_performance_prompt() -> str:
    """Get performance analysis prompt"""
    return """
PERFORMANCE ANALYSIS - Look for:
1. Inefficient algorithms
2. Memory leaks
3. Unnecessary loops or iterations
4. Inefficient data structures
5. N+1 query problems
6. Blocking operations
7. Resource not being properly closed
8. Inefficient string operations
9. Unnecessary object creation
10. Slow I/O operations
11. Missing caching opportunities
12. Inefficient database queries
13. Poor memory usage patterns
14. CPU-intensive operations
15. Scalability bottlenecks

For each issue found, provide:
ISSUE: [Brief title]
SEVERITY: [critical/high/medium/low]
TYPE: [performance issue type]
LINE: [line number where issue occurs]
DESCRIPTION: [Detailed explanation of the performance issue]
RECOMMENDATION: [How to optimize the code]
CONFIDENCE: [0.0-1.0 confidence score]

Focus on issues that could significantly impact application performance or scalability.
"""

def get_comprehensive_prompt() -> str:
    """Get comprehensive analysis prompt covering all areas"""
    return """
COMPREHENSIVE CODE ANALYSIS - Look for:

SECURITY ISSUES:
- SQL injection, XSS, authentication flaws
- Input validation, cryptographic issues
- Hardcoded secrets, path traversal
- Command injection, insecure deserialization

QUALITY ISSUES:
- Code complexity, duplicate code
- Naming conventions, error handling
- Design patterns, code smells
- Documentation, maintainability

PERFORMANCE ISSUES:
- Inefficient algorithms, memory leaks
- Poor data structures, N+1 queries
- Resource management, I/O operations
- Caching opportunities, scalability

For each issue found, provide:
ISSUE: [Brief title]
SEVERITY: [critical/high/medium/low]
TYPE: [security/quality/performance]
LINE: [line number where issue occurs]
DESCRIPTION: [Detailed explanation of the issue]
RECOMMENDATION: [How to fix/improve the code]
CONFIDENCE: [0.0-1.0 confidence score]

Prioritize critical security vulnerabilities and high-impact performance issues.
"""
