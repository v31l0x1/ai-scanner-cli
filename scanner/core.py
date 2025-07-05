"""
Core scanning functionality using Snyk CLI and Google's Gemini API
"""

import asyncio
import time
import subprocess
import json
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
import google.generativeai as genai
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .config import ScanConfig, ScanIssue, ScanResults
from .file_scanner import FileScanner
from .prompts import get_enhanced_analysis_prompt

console = Console()

class CodeScanner:
    """Main code scanner class using Snyk CLI and Gemini API"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.file_scanner = FileScanner(config)
        
        # Configure Gemini API
        genai.configure(api_key=config.api_key)
        self.model = genai.GenerativeModel('gemini-pro')
        
    def test_connection(self) -> bool:
        """Test the API connection and backend scanner availability"""
        try:
            # Test Gemini API
            response = self.model.generate_content("Hello, this is a test.")
            
            # Test backend security scanner
            result = subprocess.run(['snyk', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise Exception("Backend security scanner is not available")
            
            return True
        except Exception as e:
            raise Exception(f"Connection test failed: {str(e)}")
    
    def scan(self) -> ScanResults:
        """Perform the code scan using Snyk CLI and Gemini API"""
        start_time = time.time()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            # Step 1: Check backend scanner availability
            task1 = progress.add_task("Initializing security scanner...", total=None)
            self._check_snyk_cli()
            progress.update(task1, description="Security scanner verified")
            
            # Step 2: Run security scan
            task2 = progress.add_task("Running security analysis...", total=None)
            snyk_results = self._run_snyk_scan()
            progress.update(task2, description=f"Security analysis completed - {len(snyk_results)} issues found")
            
            # Step 3: Enhance with AI analysis
            task3 = progress.add_task("Enhancing with AI analysis...", total=len(snyk_results))
            enhanced_issues = []
            
            for i, snyk_issue in enumerate(snyk_results):
                progress.update(task3, description=f"Processing issue {i+1}/{len(snyk_results)}...")
                
                try:
                    enhanced_issue = self._enhance_issue_with_gemini(snyk_issue)
                    enhanced_issues.append(enhanced_issue)
                except Exception as e:
                    if self.config.verbose:
                        console.print(f"[red]Error enhancing issue: {str(e)}[/red]")
                    # Fallback to basic issue creation
                    enhanced_issues.append(self._create_basic_issue(snyk_issue))
                
                progress.update(task3, advance=1)
            
            progress.update(task3, description=f"AI enhancement completed - {len(enhanced_issues)} issues processed")
        
        # Filter by severity
        filtered_issues = [
            issue for issue in enhanced_issues 
            if self._severity_level(issue.severity) >= self._severity_level(self.config.min_severity)
        ]
        
        # Calculate scan duration
        scan_duration = time.time() - start_time
        
        # Create summary
        summary = self._create_summary(filtered_issues)
        
        return ScanResults(
            scan_config=self.config,
            files_scanned=len(set(issue.file_path for issue in filtered_issues)),
            issues=filtered_issues,
            scan_duration=scan_duration,
            timestamp=datetime.now().isoformat(),
            summary=summary
        )
    
    def _check_snyk_cli(self):
        """Check if backend security scanner is available"""
        try:
            result = subprocess.run(['snyk', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise Exception("Backend security scanner is not available")
        except FileNotFoundError:
            raise Exception("Backend security scanner is not installed. Please run: ai-scanner install-snyk")
        except Exception as e:
            raise Exception(f"Security scanner check failed: {str(e)}")
    
    def _run_snyk_scan(self) -> List[Dict[str, Any]]:
        """Run backend security scan and parse results"""
        try:
            # Run security scan with JSON output
            cmd = ['snyk', 'code', 'test', '--json', str(self.config.path)]
            
            if self.config.verbose:
                console.print(f"[blue]Running security analysis...[/blue]")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode not in [0, 1]:  # 0 = no issues, 1 = issues found
                raise Exception(f"Security scan failed: {result.stderr}")
            
            # Parse JSON output
            try:
                scan_data = json.loads(result.stdout)
            except json.JSONDecodeError:
                # If JSON parsing fails, try to parse text output
                return self._parse_snyk_text_output(result.stdout)
            
            return self._parse_snyk_json_output(scan_data)
            
        except subprocess.TimeoutExpired:
            raise Exception("Security scan timed out")
        except Exception as e:
            raise Exception(f"Security scan failed: {str(e)}")
    
    def _parse_snyk_json_output(self, snyk_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse Snyk JSON output"""
        issues = []
        
        if 'runs' in snyk_data:
            for run in snyk_data['runs']:
                if 'results' in run:
                    for result in run['results']:
                        issue = {
                            'rule_id': result.get('ruleId', ''),
                            'severity': self._map_snyk_severity(result.get('level', 'warning')),
                            'message': result.get('message', {}).get('text', ''),
                            'file_path': '',
                            'line_number': 1,
                            'locations': result.get('locations', [])
                        }
                        
                        # Extract file path and line number
                        if issue['locations']:
                            location = issue['locations'][0]
                            if 'physicalLocation' in location:
                                phys_loc = location['physicalLocation']
                                if 'artifactLocation' in phys_loc:
                                    issue['file_path'] = phys_loc['artifactLocation'].get('uri', '')
                                if 'region' in phys_loc:
                                    issue['line_number'] = phys_loc['region'].get('startLine', 1)
                        
                        issues.append(issue)
        
        return issues
    
    def _parse_snyk_text_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Snyk text output (fallback method)"""
        issues = []
        lines = output.split('\n')
        
        current_issue = {}
        
        for line in lines:
            line = line.strip()
            
            # Match severity and issue type
            severity_match = re.match(r'✗ \[(\w+)\] (.+)', line)
            if severity_match:
                if current_issue:
                    issues.append(current_issue)
                
                current_issue = {
                    'severity': severity_match.group(1).lower(),
                    'issue_type': severity_match.group(2),
                    'message': severity_match.group(2),
                    'file_path': '',
                    'line_number': 1,
                    'description': ''
                }
            
            # Match path and line
            path_match = re.match(r'Path: (.+), line (\d+)', line)
            if path_match and current_issue:
                current_issue['file_path'] = path_match.group(1)
                current_issue['line_number'] = int(path_match.group(2))
            
            # Match info/description
            info_match = re.match(r'Info: (.+)', line)
            if info_match and current_issue:
                current_issue['description'] = info_match.group(1)
        
        # Add the last issue
        if current_issue:
            issues.append(current_issue)
        
        return issues
    
    def _map_snyk_severity(self, snyk_severity: str) -> str:
        """Map Snyk severity to our severity levels"""
        severity_map = {
            'error': 'critical',
            'warning': 'high',
            'info': 'medium',
            'note': 'low',
            'high': 'high',
            'medium': 'medium',
            'low': 'low'
        }
        return severity_map.get(snyk_severity.lower(), 'medium')
    
    def _enhance_issue_with_gemini(self, snyk_issue: Dict[str, Any]) -> ScanIssue:
        """Enhance Snyk issue with Gemini AI analysis"""
        try:
            # Get code snippet from the file
            code_snippet = self._get_code_snippet(snyk_issue['file_path'], snyk_issue['line_number'])
            
            # Generate enhanced analysis prompt
            prompt = get_enhanced_analysis_prompt(snyk_issue, code_snippet)
            
            # Call Gemini API
            response = self.model.generate_content(prompt)
            
            # Parse enhanced response
            enhanced_data = self._parse_gemini_enhancement(response.text)
            
            return ScanIssue(
                file_path=snyk_issue['file_path'],
                line_number=snyk_issue['line_number'],
                severity=enhanced_data.get('severity', snyk_issue['severity']),
                issue_type=enhanced_data.get('issue_type', snyk_issue.get('issue_type', 'Security')),
                title=enhanced_data.get('title', snyk_issue.get('message', 'Security Issue')),
                description=enhanced_data.get('description', snyk_issue.get('description', '')),
                recommendation=enhanced_data.get('remediation', 'No remediation provided'),
                confidence=enhanced_data.get('confidence', 0.9),
                owasp_category=enhanced_data.get('owasp_category', 'Unknown'),
                code_snippet=code_snippet
            )
            
        except Exception as e:
            if self.config.verbose:
                console.print(f"[red]Error enhancing issue: {str(e)}[/red]")
            return self._create_basic_issue(snyk_issue)
    
    def _get_code_snippet(self, file_path: str, line_number: int, context_lines: int = 5) -> str:
        """Get code snippet around the specified line"""
        try:
            full_path = Path(self.config.path) / file_path
            if not full_path.exists():
                full_path = Path(file_path)
            
            if not full_path.exists():
                return "Code snippet not available"
            
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            start_line = max(0, line_number - context_lines - 1)
            end_line = min(len(lines), line_number + context_lines)
            
            snippet_lines = []
            for i in range(start_line, end_line):
                line_num = i + 1
                line_content = lines[i].rstrip()
                marker = " -> " if line_num == line_number else "    "
                snippet_lines.append(f"{line_num:4d}{marker}{line_content}")
            
            return "\n".join(snippet_lines)
            
        except Exception as e:
            return f"Error reading code snippet: {str(e)}"
    
    def _parse_gemini_enhancement(self, response_text: str) -> Dict[str, Any]:
        """Parse Gemini AI enhancement response"""
        enhanced_data = {}
        
        try:
            lines = response_text.strip().split('\n')
            current_field = None
            current_content = []
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Check if this is a field header
                if ':' in line and line.split(':')[0].upper() in ['TITLE', 'SEVERITY', 'TYPE', 'DESCRIPTION', 'REMEDIATION', 'OWASP', 'CONFIDENCE']:
                    # Save previous field if exists
                    if current_field and current_content:
                        enhanced_data[current_field] = ' '.join(current_content).strip()
                    
                    # Start new field
                    parts = line.split(':', 1)
                    field_name = parts[0].strip().upper()
                    field_value = parts[1].strip() if len(parts) > 1 else ''
                    
                    if field_name == 'SEVERITY':
                        enhanced_data['severity'] = field_value.lower()
                        current_field = None
                        current_content = []
                    elif field_name == 'TITLE':
                        enhanced_data['title'] = field_value
                        current_field = None
                        current_content = []
                    elif field_name == 'TYPE':
                        enhanced_data['issue_type'] = field_value
                        current_field = None
                        current_content = []
                    elif field_name == 'DESCRIPTION':
                        current_field = 'description'
                        current_content = [field_value] if field_value else []
                    elif field_name == 'REMEDIATION':
                        current_field = 'remediation'
                        current_content = [field_value] if field_value else []
                    elif field_name == 'OWASP':
                        enhanced_data['owasp_category'] = field_value
                        current_field = None
                        current_content = []
                    elif field_name == 'CONFIDENCE':
                        try:
                            enhanced_data['confidence'] = float(field_value)
                        except ValueError:
                            enhanced_data['confidence'] = 0.9
                        current_field = None
                        current_content = []
                else:
                    # This is continuation of previous field
                    if current_field:
                        current_content.append(line)
            
            # Save last field if exists
            if current_field and current_content:
                enhanced_data[current_field] = ' '.join(current_content).strip()
                
            # Set defaults for missing fields
            if 'remediation' not in enhanced_data or not enhanced_data['remediation']:
                enhanced_data['remediation'] = detailed_recommendations['default']
            
            if 'owasp_category' not in enhanced_data or not enhanced_data['owasp_category']:
                enhanced_data['owasp_category'] = 'A06:2021 - Vulnerable and Outdated Components'
            
            if 'description' not in enhanced_data or not enhanced_data['description']:
                enhanced_data['description'] = 'Security vulnerability detected requiring immediate attention.'
                
        except Exception as e:
            if self.config.verbose:
                console.print(f"[red]Error parsing enhancement: {str(e)}[/red]")
            # Set fallback values with detailed recommendations
            detailed_recommendations = {
                'default': """1. **Security Code Review**: Conduct thorough security code review of the affected code
2. **Input Validation**: Implement comprehensive input validation and sanitization
3. **Security Testing**: Add security-focused unit and integration tests
4. **Security Headers**: Implement appropriate security headers and configurations"""
            }
            enhanced_data = {
                'remediation': detailed_recommendations['default'],
                'owasp_category': 'A06:2021 - Vulnerable and Outdated Components',
                'description': 'Security vulnerability detected requiring immediate attention.',
                'confidence': 0.8
            }
        
        return enhanced_data
    
    def _create_basic_issue(self, snyk_issue: Dict[str, Any]) -> ScanIssue:
        """Create a basic ScanIssue from detected data (fallback)"""
        code_snippet = self._get_code_snippet(snyk_issue['file_path'], snyk_issue['line_number'])
        
        # Map common issue types to OWASP categories with more specific mappings
        issue_type = snyk_issue.get('issue_type', snyk_issue.get('message', 'Security Issue'))
        issue_message = snyk_issue.get('message', '').lower()
        
        owasp_mapping = {
            # Injection-related
            'injection': 'A03:2021 - Injection',
            'sql': 'A03:2021 - Injection',
            'xss': 'A03:2021 - Injection',
            'cross-site scripting': 'A03:2021 - Injection',
            'command injection': 'A03:2021 - Injection',
            'code injection': 'A03:2021 - Injection',
            'ldap injection': 'A03:2021 - Injection',
            'xpath injection': 'A03:2021 - Injection',
            
            # Authentication and Access Control
            'auth': 'A07:2021 - Identification and Authentication Failures',
            'authentication': 'A07:2021 - Identification and Authentication Failures',
            'authorization': 'A01:2021 - Broken Access Control',
            'access control': 'A01:2021 - Broken Access Control',
            'privilege escalation': 'A01:2021 - Broken Access Control',
            'session': 'A07:2021 - Identification and Authentication Failures',
            
            # Cryptographic issues
            'crypto': 'A02:2021 - Cryptographic Failures',
            'encryption': 'A02:2021 - Cryptographic Failures',
            'hash': 'A02:2021 - Cryptographic Failures',
            'certificate': 'A02:2021 - Cryptographic Failures',
            'ssl': 'A02:2021 - Cryptographic Failures',
            'tls': 'A02:2021 - Cryptographic Failures',
            
            # Security Misconfiguration
            'configuration': 'A05:2021 - Security Misconfiguration',
            'header': 'A05:2021 - Security Misconfiguration',
            'x-powered-by': 'A05:2021 - Security Misconfiguration',
            'server signature': 'A05:2021 - Security Misconfiguration',
            'debug': 'A05:2021 - Security Misconfiguration',
            'error message': 'A05:2021 - Security Misconfiguration',
            
            # Vulnerable Components
            'component': 'A06:2021 - Vulnerable and Outdated Components',
            'dependency': 'A06:2021 - Vulnerable and Outdated Components',
            'outdated': 'A06:2021 - Vulnerable and Outdated Components',
            'vulnerable': 'A06:2021 - Vulnerable and Outdated Components',
            
            # Deserialization
            'deserialization': 'A08:2021 - Software and Data Integrity Failures',
            'serialization': 'A08:2021 - Software and Data Integrity Failures',
            'pickle': 'A08:2021 - Software and Data Integrity Failures',
            
            # Logging and Monitoring
            'logging': 'A09:2021 - Security Logging and Monitoring Failures',
            'monitoring': 'A09:2021 - Security Logging and Monitoring Failures',
            'audit': 'A09:2021 - Security Logging and Monitoring Failures',
            
            # SSRF
            'ssrf': 'A10:2021 - Server-Side Request Forgery',
            'server-side request': 'A10:2021 - Server-Side Request Forgery',
            'request forgery': 'A10:2021 - Server-Side Request Forgery',
            
            # Input Validation
            'input validation': 'A03:2021 - Injection',
            'path traversal': 'A01:2021 - Broken Access Control',
            'directory traversal': 'A01:2021 - Broken Access Control',
            'file inclusion': 'A01:2021 - Broken Access Control',
            
            # DoS and Resource Issues
            'denial of service': 'A05:2021 - Security Misconfiguration',
            'resource exhaustion': 'A05:2021 - Security Misconfiguration',
            'rate limiting': 'A05:2021 - Security Misconfiguration',
        }
        
        # Try to map to OWASP category
        owasp_category = 'A06:2021 - Vulnerable and Outdated Components'  # Default
        
        # Check issue type and message for OWASP mapping
        combined_text = f"{issue_type} {issue_message}".lower()
        for key, value in owasp_mapping.items():
            if key.lower() in combined_text:
                owasp_category = value
                break
        
        # Generate appropriate recommendation based on issue type
        detailed_recommendations = {
            'injection': {
                'sql': """1. **Use Parameterized Queries**: Replace string concatenation with parameterized queries or prepared statements:
   ```javascript
   // Instead of: SELECT * FROM users WHERE id = '${userId}'
   const query = 'SELECT * FROM users WHERE id = ?';
   db.get(query, [userId], callback);
   ```
2. **Input Validation**: Implement strict input validation and sanitization
3. **Use ORM/Query Builders**: Consider using libraries like Sequelize or Prisma
4. **Least Privilege**: Ensure database user has minimal required permissions""",
                
                'xss': """1. **Output Encoding**: Use proper output encoding for user data:
   ```javascript
   // Instead of: res.send(`<h1>Welcome ${username}</h1>`)
   const escapeHtml = require('escape-html');
   res.send(`<h1>Welcome ${escapeHtml(username)}</h1>`);
   ```
2. **Content Security Policy**: Implement CSP headers to prevent script injection
3. **Use Template Engines**: Use secure template engines with auto-escaping (e.g., Handlebars with escape)
4. **Validate Input**: Implement strict input validation and sanitization""",
                
                'command': """1. **Avoid Dynamic Command Execution**: Never execute user input as system commands:
   ```javascript
   // Instead of: exec(userInput)
   // Use predefined command mapping:
   const allowedCommands = { 'list': 'ls -la', 'date': 'date' };
   const command = allowedCommands[userInput];
   if (command) exec(command);
   ```
2. **Input Validation**: Implement strict whitelist validation for any command parameters
3. **Use Safe Libraries**: Use safer alternatives like specific Node.js modules for file operations
4. **Sandboxing**: If command execution is necessary, use sandboxed environments""",
                
                'default': """1. **Input Sanitization**: Implement comprehensive input validation and sanitization
2. **Use Parameterized Queries**: Replace string concatenation with parameterized queries
3. **Output Encoding**: Apply proper output encoding based on context (HTML, URL, JavaScript)
4. **Security Headers**: Implement appropriate security headers (CSP, X-Frame-Options, etc.)"""
            },
            'auth': """1. **Strong Authentication**: Implement multi-factor authentication and strong password policies
2. **Session Management**: Use secure session management with proper timeout and regeneration
3. **Password Hashing**: Use strong hashing algorithms (bcrypt, scrypt, or Argon2)
4. **Rate Limiting**: Implement account lockout and rate limiting for login attempts""",
            'crypto': """1. **Use Strong Algorithms**: Replace weak algorithms with AES-256, RSA-2048+, or modern alternatives
2. **Secure Key Management**: Use dedicated key management systems and avoid hardcoded keys
3. **Proper Random Generation**: Use cryptographically secure random number generators
4. **Update Libraries**: Keep cryptographic libraries updated to latest versions""",
            'component': """1. **Update Dependencies**: Update all dependencies to latest secure versions:
   ```bash
   npm audit fix
   npm update
   ```
2. **Monitor Vulnerabilities**: Use tools like Snyk or npm audit to monitor for new vulnerabilities
3. **Pin Versions**: Pin dependency versions and test updates before deployment
4. **Remove Unused Dependencies**: Remove unnecessary packages to reduce attack surface""",
            'configuration': """1. **Security Headers**: Implement comprehensive security headers:
   ```javascript
   app.use(helmet()); // Use Helmet.js for Express
   ```
2. **Disable Debug Info**: Remove debug information and error details from production
3. **Secure Defaults**: Use secure configuration defaults and hardening guides
4. **Regular Security Reviews**: Conduct regular security configuration reviews""",
            'default': """1. **Security Code Review**: Conduct thorough security code review of the affected code
2. **Input Validation**: Implement comprehensive input validation and sanitization
3. **Security Testing**: Add security-focused unit and integration tests
4. **Security Headers**: Implement appropriate security headers and configurations"""
        }
        
        # Determine the specific recommendation based on issue type
        issue_type_lower = issue_type.lower()
        recommendation = detailed_recommendations['default']
        
        if 'sql' in issue_type_lower or 'injection' in issue_type_lower:
            if 'sql' in issue_type_lower:
                recommendation = detailed_recommendations['injection']['sql']
            elif 'xss' in issue_type_lower or 'cross-site' in issue_type_lower:
                recommendation = detailed_recommendations['injection']['xss']
            elif 'command' in issue_type_lower:
                recommendation = detailed_recommendations['injection']['command']
            else:
                recommendation = detailed_recommendations['injection']['default']
        elif 'auth' in issue_type_lower or 'password' in issue_type_lower:
            recommendation = detailed_recommendations['auth']
        elif 'crypto' in issue_type_lower or 'encrypt' in issue_type_lower:
            recommendation = detailed_recommendations['crypto']
        elif 'component' in issue_type_lower or 'dependency' in issue_type_lower:
            recommendation = detailed_recommendations['component']
        elif 'config' in issue_type_lower or 'header' in issue_type_lower:
            recommendation = detailed_recommendations['configuration']
        
        return ScanIssue(
            file_path=snyk_issue['file_path'],
            line_number=snyk_issue['line_number'],
            severity=snyk_issue['severity'],
            issue_type=issue_type,
            title=snyk_issue.get('message', 'Security Vulnerability Detected'),
            description=snyk_issue.get('description', 'A security vulnerability has been detected in your code that requires attention.'),
            recommendation=recommendation,
            confidence=0.8,
            owasp_category=owasp_category,
            code_snippet=code_snippet
        )
    
    def _severity_level(self, severity: str) -> int:
        """Convert severity string to numeric level"""
        levels = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return levels.get(severity.lower(), 2)
    
    def _create_summary(self, issues: List[ScanIssue]) -> Dict[str, Any]:
        """Create a summary of scan results"""
        summary = {
            'total_issues': len(issues),
            'by_severity': {},
            'by_type': {},
            'by_owasp': {},
            'files_with_issues': len(set(issue.file_path for issue in issues))
        }
        
        # Count by severity
        for issue in issues:
            severity = issue.severity
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
        
        # Count by type
        for issue in issues:
            issue_type = issue.issue_type
            summary['by_type'][issue_type] = summary['by_type'].get(issue_type, 0) + 1
        
        # Count by OWASP category
        for issue in issues:
            owasp = issue.owasp_category
            summary['by_owasp'][owasp] = summary['by_owasp'].get(owasp, 0) + 1
        
        return summary
