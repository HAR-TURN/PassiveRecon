"""
Information Leakage Detection Module
Detects leaked API keys, admin panels, sensitive endpoints, tokens.
"""

import re
from bs4 import BeautifulSoup


class InfoLeakageModule:
    """Detects information leakage in responses."""

    API_KEY_PATTERNS = {
        'AWS Access Key': r'AKIA[0-9A-Z]{16}',
        'AWS Secret Key': r'(?i)aws(.{0,20})?(?-i)[\'"][0-9a-zA-Z\/+]{40}[\'"]',
        'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
        'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'Firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
        'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
        'GitHub Token': r'gh[ps]_[A-Za-z0-9_]{36}',
        'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24}',
        'Stripe Publishable Key': r'pk_live_[0-9a-zA-Z]{24}',
        'Square OAuth': r'sq0atp-[0-9A-Za-z\-_]{22}',
        'Square Access Token': r'sq0csp-[0-9A-Za-z\-_]{43}',
        'Twilio API Key': r'SK[0-9a-fA-F]{32}',
        'SendGrid API Key': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
        'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
        'Heroku API Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'JWT Token': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        'Private Key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        'Generic API Key': r'(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*[\'"]?([a-zA-Z0-9\-_]{20,})[\'"]?',
        'Generic Secret': r'(?i)(secret|password|passwd|pwd)\s*[:=]\s*[\'"]?([^\s\'"]{8,})[\'"]?',
        'Bearer Token': r'(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}',
        'Basic Auth': r'(?i)basic\s+[a-zA-Z0-9+/=]{20,}',
        'MongoDB URI': r'mongodb(?:\+srv)?://[^\s<>"]+',
        'Database URL': r'(?i)(mysql|postgres|postgresql|redis|mongodb)://[^\s<>"\']+',
    }

    ADMIN_PATHS = [
        '/admin', '/admin/', '/administrator', '/admin/login',
        '/wp-admin', '/wp-login.php', '/login', '/admin.php',
        '/panel', '/dashboard', '/manage', '/manager',
        '/cpanel', '/phpmyadmin', '/adminer', '/webadmin',
        '/cms', '/backend', '/control', '/controlpanel',
        '/admin/dashboard', '/admin/index', '/adminpanel',
        '/siteadmin', '/system', '/moderator',
        '/.env', '/config', '/configuration',
        '/api/admin', '/api/config', '/api/debug',
        '/debug', '/trace', '/test', '/info',
        '/server-status', '/server-info',
        '/elmah.axd', '/phpinfo.php',
    ]

    SENSITIVE_FILES = [
        '/.env', '/.git/config', '/.gitignore', '/.svn/entries',
        '/web.config', '/crossdomain.xml', '/.htaccess',
        '/package.json', '/composer.json', '/Gemfile',
        '/wp-config.php.bak', '/config.php.bak',
        '/backup.zip', '/backup.sql', '/dump.sql',
        '/.DS_Store', '/Thumbs.db',
        '/swagger.json', '/api-docs', '/openapi.json',
        '/graphql', '/graphiql',
    ]

    def __init__(self, client, parsed_url, response, verbose=False):
        self.client = client
        self.parsed_url = parsed_url
        self.response = response
        self.verbose = verbose

    def run(self):
        findings = []
        score = 100

        body = self.response.text
        headers = self.response.headers

        # Check for API keys in response body
        leaked_keys = self._scan_for_keys(body)
        for key_type, matches in leaked_keys.items():
            for match in matches:
                # Truncate for safety
                truncated = match[:30] + '...' if len(match) > 30 else match
                findings.append({
                    'type': 'leaked_key',
                    'severity': 'critical',
                    'description': f"Possible {key_type} leaked: {truncated}",
                    'recommendation': f"Remove {key_type} from client-side code immediately"
                })
                score -= 15

        # Check for sensitive info in HTML comments
        comment_leaks = self._check_comments(body)
        for leak in comment_leaks:
            findings.append({
                'type': 'comment_leak',
                'severity': 'medium',
                'description': f"Sensitive info in HTML comment: {leak[:100]}",
                'recommendation': 'Remove sensitive information from HTML comments'
            })
            score -= 5

        # Check admin panels and sensitive paths
        admin_found = self._check_admin_paths()
        for path, status in admin_found:
            severity = 'high' if status == 200 else 'medium'
            findings.append({
                'type': 'admin_panel',
                'severity': severity,
                'description': f"Admin/sensitive path accessible: {path} (HTTP {status})",
                'recommendation': f"Restrict access to {path} or remove if unused"
            })
            score -= 10 if status == 200 else 3

        # Check sensitive files
        sensitive_found = self._check_sensitive_files()
        for path, status in sensitive_found:
            findings.append({
                'type': 'sensitive_file',
                'severity': 'critical' if status == 200 else 'low',
                'description': f"Sensitive file accessible: {path} (HTTP {status})",
                'recommendation': f"Remove or restrict access to {path}"
            })
            score -= 15 if status == 200 else 2

        # Check for error messages / stack traces
        error_leaks = self._check_error_disclosure(body)
        for leak in error_leaks:
            findings.append({
                'type': 'error_disclosure',
                'severity': 'medium',
                'description': f"Error/debug information disclosed: {leak}",
                'recommendation': 'Disable debug mode and customize error pages'
            })
            score -= 5

        # Check for email addresses
        emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', body)
        unique_emails = list(set(emails))[:10]  # Limit
        if unique_emails:
            findings.append({
                'type': 'email_disclosure',
                'severity': 'low',
                'description': f"Email addresses found: {', '.join(unique_emails[:5])}",
                'recommendation': 'Consider obfuscating email addresses'
            })
            score -= 2

        # Check for internal IP addresses
        internal_ips = re.findall(r'\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b', body)
        if internal_ips:
            findings.append({
                'type': 'internal_ip',
                'severity': 'medium',
                'description': f"Internal IP addresses found: {', '.join(set(internal_ips))}",
                'recommendation': 'Remove internal IP addresses from public responses'
            })
            score -= 5

        # Check response headers for info leaks
        header_leaks = self._check_header_leaks(headers)
        findings.extend(header_leaks)
        score -= len(header_leaks) * 3

        score = max(0, score)
        grade = self._score_to_grade(score)

        return {
            'module': 'Information Leakage',
            'grade': grade,
            'score': score,
            'leaked_keys_count': sum(len(v) for v in leaked_keys.values()),
            'admin_panels_found': len(admin_found),
            'sensitive_files_found': len(sensitive_found),
            'findings': findings
        }

    def _scan_for_keys(self, text):
        """Scan text for API keys and secrets."""
        results = {}
        for key_type, pattern in self.API_KEY_PATTERNS.items():
            try:
                matches = re.findall(pattern, text)
                if matches:
                    # Handle tuples from groups
                    clean_matches = []
                    for m in matches:
                        if isinstance(m, tuple):
                            clean_matches.append(m[-1])
                        else:
                            clean_matches.append(m)
                    results[key_type] = list(set(clean_matches))[:3]
            except re.error:
                continue
        return results

    def _check_comments(self, body):
        """Check HTML comments for sensitive info."""
        comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
        sensitive_patterns = [
            r'(?i)(password|passwd|pwd|secret|api.?key|token|admin|root|debug|todo|fixme|hack|bug|credential)',
            r'(?i)(database|db_|mysql|postgres|mongo|redis|config|internal)',
        ]
        suspicious = []
        for comment in comments:
            for pattern in sensitive_patterns:
                if re.search(pattern, comment):
                    suspicious.append(comment.strip()[:200])
                    break
        return suspicious

    def _check_admin_paths(self):
        """Check for accessible admin paths (limited, passive)."""
        found = []
        # Only check a few critical ones to be non-intrusive
        critical_paths = ['/admin', '/login', '/wp-admin', '/wp-login.php',
                          '/.env', '/api/config', '/debug', '/phpinfo.php',
                          '/administrator', '/panel']

        for path in critical_paths[:8]:  # Limit checks
            url = self.parsed_url['base_url'] + path
            resp = self.client.head(url)
            if resp and resp.status_code in [200, 301, 302, 403]:
                found.append((path, resp.status_code))

        return found

    def _check_sensitive_files(self):
        """Check for accessible sensitive files."""
        found = []
        priority_files = ['/.env', '/.git/config', '/package.json',
                          '/swagger.json', '/openapi.json', '/graphql',
                          '/crossdomain.xml', '/phpinfo.php']

        for path in priority_files:
            url = self.parsed_url['base_url'] + path
            resp = self.client.head(url)
            if resp and resp.status_code == 200:
                found.append((path, resp.status_code))

        return found

    def _check_error_disclosure(self, body):
        """Check for error messages and stack traces."""
        error_patterns = [
            (r'(?i)fatal error:', 'PHP Fatal Error'),
            (r'(?i)stack trace:', 'Stack Trace'),
            (r'(?i)traceback \(most recent', 'Python Traceback'),
            (r'(?i)exception in thread', 'Java Exception'),
            (r'(?i)server error in .* application', 'ASP.NET Error'),
            (r'(?i)syntax error', 'Syntax Error'),
            (r'(?i)mysql_fetch|mysql_connect|mysqli_', 'MySQL Error'),
            (r'(?i)pg_query|pg_connect', 'PostgreSQL Error'),
            (r'(?i)ORA-\d{5}', 'Oracle Error'),
            (r'(?i)Microsoft OLE DB', 'MSSQL Error'),
        ]

        leaks = []
        for pattern, name in error_patterns:
            if re.search(pattern, body):
                leaks.append(name)

        return leaks

    def _check_header_leaks(self, headers):
        """Check headers for information leaks."""
        leaks = []
        sensitive_headers = {
            'X-Debug-Token': 'Debug token',
            'X-Debug-Token-Link': 'Debug link',
            'X-Powered-CMS': 'CMS disclosure',
            'X-Backend-Server': 'Backend server',
            'X-Runtime': 'Runtime info',
        }

        for header, desc in sensitive_headers.items():
            if headers.get(header):
                leaks.append({
                    'type': 'header_leak',
                    'severity': 'medium',
                    'description': f"{desc} via {header}: {headers[header]}",
                    'recommendation': f"Remove {header} header from responses"
                })

        return leaks

    def _score_to_grade(self, score):
        if score >= 95: return 'A+'
        elif score >= 90: return 'A'
        elif score >= 85: return 'A-'
        elif score >= 80: return 'B+'
        elif score >= 75: return 'B'
        elif score >= 70: return 'B-'
        elif score >= 65: return 'C+'
        elif score >= 60: return 'C'
        elif score >= 55: return 'C-'
        elif score >= 50: return 'D'
        else: return 'F'

      
