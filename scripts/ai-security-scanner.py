#!/usr/bin/env python3
"""
AI-Powered Security Scanner for .NET Applications
Combines static analysis with AI-driven vulnerability detection
"""

import json
import sys
import os
import re
import ast
from pathlib import Path
import openai
from datetime import datetime
import hashlib

class SecurityScanner:
    def __init__(self):
        self.setup_openai()
        self.vulnerability_patterns = self.load_vulnerability_patterns()
        
    def setup_openai(self):
        """Configure OpenAI API"""
        self.api_key = os.getenv('OPENAI_API_KEY')
        if not self.api_key and os.getenv('AZURE_OPENAI_KEY'):
            openai.api_type = "azure"
            openai.api_key = os.getenv('AZURE_OPENAI_KEY')
            openai.api_base = os.getenv('AZURE_OPENAI_ENDPOINT')
            openai.api_version = "2023-12-01-preview"
        else:
            openai.api_key = self.api_key
    
    def load_vulnerability_patterns(self):
        """Load common C# vulnerability patterns"""
        return {
            'sql_injection': [
                r'string.*sql.*\+.*',
                r'String\.Format\(.*SELECT.*\{.*\}',
                r'SqlCommand\([^@]*["\'].*["\'][^@]*\)',
                r'ExecuteSqlRaw\([^@]*["\'].*["\'][^@]*\)'
            ],
            'xss': [
                r'Html\.Raw\(',
                r'@Html\.Raw\(',
                r'innerHTML\s*=',
                r'document\.write\(',
                r'Response\.Write\([^HttpUtility]'
            ],
            'hardcoded_secrets': [
                r'(password|pwd|secret|key|token|api[_-]?key)\s*=\s*["\'][^"\']{8,}["\']',
                r'connectionString.*password\s*=\s*[^;]+',
                r'(Bearer\s+[A-Za-z0-9\-_]{20,})',
                r'(sk-[A-Za-z0-9]{40,})',  # OpenAI API keys
                r'([A-Za-z0-9]{32})',  # MD5-like keys
            ],
            'deserialization': [
                r'JsonConvert\.DeserializeObject.*TypeNameHandling',
                r'BinaryFormatter\.Deserialize',
                r'XmlSerializer\.Deserialize.*[^XmlReaderSettings]',
                r'JavaScriptSerializer\.Deserialize'
            ],
            'path_traversal': [
                r'File\.(ReadAllText|WriteAllText|Delete|Move|Copy)\([^Path\.Combine].*\+',
                r'Directory\.(Delete|Move|CreateDirectory)\([^Path\.Combine].*\+',
                r'FileStream\([^Path\.Combine].*\+'
            ],
            'weak_crypto': [
                r'MD5\.Create\(\)',
                r'SHA1\.Create\(\)',
                r'DESCryptoServiceProvider',
                r'RC2CryptoServiceProvider',
                r'Random\(\)\.Next\(',  # Weak random for crypto
            ],
            'authentication_bypass': [
                r'FormsAuthentication\.SetAuthCookie\([^,]*,\s*true\)',
                r'ClaimsIdentity\([^,]*,\s*null\)',
                r'Thread\.CurrentPrincipal\s*=.*new.*Principal',
                r'HttpContext\.User\s*='
            ],
            'information_disclosure': [
                r'Exception\.(Message|StackTrace|ToString\(\))',
                r'Console\.WriteLine\(.*Exception',
                r'Debug\.WriteLine\(.*Exception',
                r'Response\.Write\(.*Exception'
            ],
            'unsafe_reflection': [
                r'Assembly\.LoadFrom\([^@]',
                r'Activator\.CreateInstance\(.*Type\.GetType\(',
                r'Type\.GetType\([^"].*[^")]',
                r'AppDomain\.CurrentDomain\.Load'
            ],
            'csrf': [
                r'\[HttpPost\](?!.*\[ValidateAntiForgeryToken\])',
                r'@Html\.ActionLink.*method.*post',
                r'$.post\(',
                r'XMLHttpRequest.*POST'
            ]
        }
    
    def scan_file(self, file_path):
        """Scan a single C# file for vulnerabilities"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            vulnerabilities = []
            
            # Pattern-based detection
            for vuln_type, patterns in self.vulnerability_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        vulnerabilities.append({
                            'type': vuln_type,
                            'severity': self.get_severity(vuln_type),
                            'line': line_num,
                            'pattern': pattern,
                            'match': match.group(0)[:100],  # Limit match length
                            'description': self.get_vulnerability_description(vuln_type)
                        })
            
            # Additional context analysis
            file_analysis = {
                'file_path': str(file_path),
                'file_hash': hashlib.md5(content.encode()).hexdigest(),
                'lines_of_code': len(content.splitlines()),
                'vulnerabilities': vulnerabilities,
                'code_snippet': content[:2000] if len(content) > 2000 else content,
                'has_controllers': 'Controller' in content and 'public class' in content,
                'has_models': 'public class' in content and any(attr in content for attr in ['[Key]', '[Required]', 'DbContext']),
                'has_authentication': any(auth in content for auth in ['[Authorize]', 'ClaimsPrincipal', 'Identity'])
            }
            
            return file_analysis
            
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
            return None
    
    def get_severity(self, vuln_type):
        """Get severity level for vulnerability type"""
        severity_map = {
            'sql_injection': 'Critical',
            'xss': 'High',
            'hardcoded_secrets': 'Critical',
            'deserialization': 'High',
            'path_traversal': 'High',
            'weak_crypto': 'Medium',
            'authentication_bypass': 'Critical',
            'information_disclosure': 'Medium',
            'unsafe_reflection': 'High',
            'csrf': 'Medium'
        }
        return severity_map.get(vuln_type, 'Low')
    
    def get_vulnerability_description(self, vuln_type):
        """Get description for vulnerability type"""
        descriptions = {
            'sql_injection': 'SQL Injection vulnerability - user input concatenated with SQL queries',
            'xss': 'Cross-Site Scripting vulnerability - unescaped output to HTML',
            'hardcoded_secrets': 'Hard-coded credentials or secrets in source code',
            'deserialization': 'Unsafe deserialization that could lead to code execution',
            'path_traversal': 'Path traversal vulnerability allowing file system access',
            'weak_crypto': 'Use of weak or obsolete cryptographic algorithms',
            'authentication_bypass': 'Authentication bypass or weak authentication implementation',
            'information_disclosure': 'Information disclosure through error messages or logging',
            'unsafe_reflection': 'Unsafe use of reflection that could lead to code injection',
            'csrf': 'Cross-Site Request Forgery vulnerability - missing CSRF protection'
        }
        return descriptions.get(vuln_type, 'Security vulnerability detected')
    
    def ai_analyze_code(self, file_analysis):
        """Use AI to analyze code for additional vulnerabilities"""
        if not self.api_key and not os.getenv('AZURE_OPENAI_KEY'):
            return []
        
        # Focus on files with existing vulnerabilities or high-risk patterns
        if not file_analysis['vulnerabilities'] and not file_analysis['has_controllers']:
            return []
        
        prompt = f"""
        Analyze this C# code for security vulnerabilities:
        
        File: {file_analysis['file_path']}
        Type: {"Controller" if file_analysis['has_controllers'] else "Model" if file_analysis['has_models'] else "Other"}
        
        Code:
        {file_analysis['code_snippet']}
        
        Look for:
        1. SQL injection vulnerabilities (especially in LINQ, Entity Framework, raw SQL)
        2. Cross-site scripting (XSS) in view rendering
        3. Authentication and authorization flaws
        4. Input validation issues
        5. Business logic vulnerabilities
        6. Race conditions and concurrency issues
        7. Improper error handling that leaks information
        8. Missing security headers or configurations
        9. Insecure direct object references
        10. Security misconfigurations
        
        For each vulnerability found, provide:
        - Type of vulnerability
        - Severity (Critical/High/Medium/Low)
        - Specific line or code pattern if possible
        - Brief explanation
        - Mitigation recommendation
        
        Return as JSON array of vulnerability objects.
        """
        
        try:
            if openai.api_type == "azure":
                response = openai.ChatCompletion.create(
                    engine="gpt-4",
                    messages=[
                        {
                            "role": "system", 
                            "content": "You are a security expert analyzing C# code for vulnerabilities. Respond with valid JSON only."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=2000,
                    temperature=0.1
                )
            else:
                response = openai.ChatCompletion.create(
                    model="gpt-4",
                    messages=[
                        {
                            "role": "system", 
                            "content": "You are a security expert analyzing C# code for vulnerabilities. Respond with valid JSON only."
                        },
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=2000,
                    temperature=0.1
                )
            
            ai_response = response.choices[0].message.content.strip()
            
            # Clean up response to extract JSON
            if '```json' in ai_response:
                ai_response = ai_response.split('```json')[1].split('```')[0]
            elif '```' in ai_response:
                ai_response = ai_response.split('```')[1]
            
            try:
                vulnerabilities = json.loads(ai_response)
                if isinstance(vulnerabilities, list):
                    return vulnerabilities
                else:
                    return []
            except json.JSONDecodeError:
                # If we can't parse JSON, try to extract vulnerabilities from text
                return self.parse_text_vulnerabilities(ai_response)
                
        except Exception as e:
            print(f"AI analysis failed for {file_analysis['file_path']}: {e}")
            return []
    
    def parse_text_vulnerabilities(self, text_response):
        """Parse vulnerability information from text response"""
        vulnerabilities = []
        
        # Simple text parsing for common vulnerability mentions
        severity_keywords = {
            'critical': 'Critical',
            'high': 'High', 
            'medium': 'Medium',
            'low': 'Low'
        }
        
        lines = text_response.split('\n')
        current_vuln = {}
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Look for vulnerability indicators
            if any(keyword in line.lower() for keyword in ['vulnerability', 'injection', 'xss', 'csrf']):
                if current_vuln:
                    vulnerabilities.append(current_vuln)
                current_vuln = {
                    'type': 'ai_detected',
                    'description': line,
                    'severity': 'Medium'
                }
                
                # Try to extract severity
                for keyword, severity in severity_keywords.items():
                    if keyword in line.lower():
                        current_vuln['severity'] = severity
                        break
        
        if current_vuln:
            vulnerabilities.append(current_vuln)
            
        return vulnerabilities[:5]  # Limit to prevent noise
    
    def generate_security_report(self, scan_results, output_dir):
        """Generate comprehensive security report"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Aggregate statistics
        total_files = len(scan_results)
        total_vulnerabilities = sum(len(r.get('vulnerabilities', [])) + len(r.get('ai_vulnerabilities', [])) for r in scan_results)
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        vuln_types = {}
        
        for result in scan_results:
            for vuln in result.get('vulnerabilities', []) + result.get('ai_vulnerabilities', []):
                severity = vuln.get('severity', 'Low')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                vuln_type = vuln.get('type', 'unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        # Generate detailed report
        report = {
            'scan_date': datetime.now().isoformat(),
            'summary': {
                'total_files_scanned': total_files,
                'total_vulnerabilities': total_vulnerabilities,
                'severity_breakdown': severity_counts,
                'vulnerability_types': vuln_types
            },
            'files': scan_results,
            'recommendations': self.generate_recommendations(severity_counts, vuln_types)
        }
        
        # Save JSON report
        json_file = Path(output_dir) / 'security_scan_report.json'
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Generate markdown summary
        self.generate_markdown_report(report, Path(output_dir) / 'security_summary.md')
        
        # Generate SARIF format for integration with security tools
        self.generate_sarif_report(scan_results, Path(output_dir) / 'security_scan.sarif')
        
        print(f"Security reports generated in {output_dir}")
        return report
    
    def generate_recommendations(self, severity_counts, vuln_types):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if severity_counts['Critical'] > 0:
            recommendations.append({
                'priority': 'Critical',
                'action': f"Immediately address {severity_counts['Critical']} critical vulnerabilities",
                'description': 'Critical vulnerabilities pose immediate risk and should be fixed before deployment'
            })
        
        if 'sql_injection' in vuln_types:
            recommendations.append({
                'priority': 'High',
                'action': 'Implement parameterized queries and ORM best practices',
                'description': 'Replace string concatenation in SQL with parameters or stored procedures'
            })
        
        if 'xss' in vuln_types:
            recommendations.append({
                'priority': 'High', 
                'action': 'Implement proper output encoding and CSP headers',
                'description': 'Use HTML encoding for all user input displayed in web pages'
            })
        
        if 'hardcoded_secrets' in vuln_types:
            recommendations.append({
                'priority': 'Critical',
                'action': 'Move secrets to secure configuration management',
                'description': 'Use Azure Key Vault, environment variables, or secure config files'
            })
        
        if severity_counts['High'] + severity_counts['Critical'] > 10:
            recommendations.append({
                'priority': 'High',
                'action': 'Implement security code review process',
                'description': 'High number of security issues indicates need for systematic security reviews'
            })
        
        recommendations.append({
            'priority': 'Medium',
            'action': 'Integrate security scanning in CI/CD pipeline',
            'description': 'Prevent security vulnerabilities from reaching production'
        })
        
        return recommendations
    
    def generate_markdown_report(self, report, output_file):
        """Generate markdown security report"""
        summary = report['summary']
        
        markdown = f"""# Security Scan Report
        
Generated: {report['scan_date']}

## Executive Summary

- **Files Scanned**: {summary['total_files_scanned']}
- **Total Vulnerabilities**: {summary['total_vulnerabilities']}
- **Risk Level**: {"🔴 Critical" if summary['severity_breakdown']['Critical'] > 0 else "🟡 High" if summary['severity_breakdown']['High'] > 0 else "🟢 Low"}

## Severity Breakdown

| Severity | Count |
|----------|-------|
| Critical | {summary['severity_breakdown']['Critical']} |
| High     | {summary['severity_breakdown']['High']} |
| Medium   | {summary['severity_breakdown']['Medium']} |
| Low      | {summary['severity_breakdown']['Low']} |

## Top Vulnerability Types

"""
        
        for vuln_type, count in sorted(summary['vulnerability_types'].items(), key=lambda x: x[1], reverse=True)[:10]:
            markdown += f"- **{vuln_type.replace('_', ' ').title()}**: {count} occurrences\n"
        
        markdown += "\n## Priority Recommendations\n\n"
        
        for rec in report['recommendations'][:5]:
            icon = "🔴" if rec['priority'] == 'Critical' else "🟡" if rec['priority'] == 'High' else "🔵"
            markdown += f"{icon} **{rec['action']}**\n{rec['description']}\n\n"
        
        # Top vulnerable files
        vulnerable_files = [(f['file_path'], len(f.get('vulnerabilities', [])) + len(f.get('ai_vulnerabilities', []))) 
                          for f in report['files']]
        vulnerable_files = sorted(vulnerable_files, key=lambda x: x[1], reverse=True)[:10]
        
        if vulnerable_files:
            markdown += "## Most Vulnerable Files\n\n"
            for file_path, vuln_count in vulnerable_files:
                if vuln_count > 0:
                    markdown += f"- `{file_path}`: {vuln_count} issues\n"
        
        with open(output_file, 'w') as f:
            f.write(markdown)
    
    def generate_sarif_report(self, scan_results, output_file):
        """Generate SARIF format report for tool integration"""
        sarif_report = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AI Security Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/your-org/security-scanner"
                    }
                },
                "results": []
            }]
        }
        
        for result in scan_results:
            file_path = result['file_path']
            
            for vuln in result.get('vulnerabilities', []) + result.get('ai_vulnerabilities', []):
                sarif_result = {
                    "ruleId": vuln.get('type', 'security_issue'),
                    "message": {
                        "text": vuln.get('description', 'Security vulnerability detected')
                    },
                    "level": self.severity_to_sarif_level(vuln.get('severity', 'Medium')),
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path
                            },
                            "region": {
                                "startLine": vuln.get('line', 1)
                            }
                        }
                    }]
                }
                
                sarif_report["runs"][0]["results"].append(sarif_result)
        
        with open(output_file, 'w') as f:
            json.dump(sarif_report, f, indent=2)
    
    def severity_to_sarif_level(self, severity):
        """Convert severity to SARIF level"""
        mapping = {
            'Critical': 'error',
            'High': 'error', 
            'Medium': 'warning',
            'Low': 'note'
        }
        return mapping.get(severity, 'warning')

def main():
    if len(sys.argv) < 2:
        print("Usage: python ai-security-scanner.py <source_directory> [output_directory]")
        sys.exit(1)
    
    source_dir = Path(sys.argv[1])
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "security-reports"
    
    if not source_dir.exists():
        print(f"Source directory {source_dir} does not exist")
        sys.exit(1)
    
    scanner = SecurityScanner()
    
    print(f"🔍 Starting security scan of {source_dir}")
    
    # Find C# files
    cs_files = list(source_dir.rglob("*.cs"))
    cs_files = [f for f in cs_files if not any(exclude in str(f) for exclude in 
                                             ['bin', 'obj', 'packages', 'node_modules'])]
    
    if not cs_files:
        print("No C# files found to scan")
        sys.exit(1)
    
    print(f"Found {len(cs_files)} C# files to analyze")
    
    scan_results = []
    
    for i, cs_file in enumerate(cs_files):
        print(f"Scanning {cs_file} ({i+1}/{len(cs_files)})")
        
        file_analysis = scanner.scan_file(cs_file)
        if file_analysis:
            # Add AI analysis for high-risk files
            if (file_analysis['vulnerabilities'] or 
                file_analysis['has_controllers'] or 
                file_analysis['has_authentication']):
                
                print(f"  Running AI analysis...")
                ai_vulnerabilities = scanner.ai_analyze_code(file_analysis)
                file_analysis['ai_vulnerabilities'] = ai_vulnerabilities
            else:
                file_analysis['ai_vulnerabilities'] = []
            
            scan_results.append(file_analysis)
    
    print("📊 Generating security report...")
    report = scanner.generate_security_report(scan_results, output_dir)
    
    # Print summary
    summary = report['summary']
    print(f"\n✅ Security scan complete!")
    print(f"   Files scanned: {summary['total_files_scanned']}")
    print(f"   Vulnerabilities found: {summary['total_vulnerabilities']}")
    print(f"   Critical: {summary['severity_breakdown']['Critical']}")
    print(f"   High: {summary['severity_breakdown']['High']}")
    print(f"   Medium: {summary['severity_breakdown']['Medium']}")
    print(f"   Low: {summary['severity_breakdown']['Low']}")
    print(f"\n📁 Reports saved to: {output_dir}")

if __name__ == "__main__":
    main()