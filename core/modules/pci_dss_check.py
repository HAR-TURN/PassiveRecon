"""
PCI DSS Compliance Indicators Module
"""


class PCIDSSCheckModule:
    """Checks for PCI DSS compliance indicators."""

    def __init__(self, client, parsed_url, response, verbose=False):
        self.client = client
        self.parsed_url = parsed_url
        self.response = response
        self.verbose = verbose

    def run(self):
        findings = []
        score = 100
        checks = {}

        headers = self.response.headers

        # PCI DSS Requirement 4: Encrypt transmission of cardholder data
        if self.parsed_url['scheme'] != 'https':
            findings.append({
                'type': 'no_encryption',
                'severity': 'critical',
                'description': 'PCI DSS 4.1: No HTTPS encryption for data transmission',
                'recommendation': 'Enable HTTPS for all pages'
            })
            score -= 30
            checks['encryption'] = 'FAIL'
        else:
            checks['encryption'] = 'PASS'

        # HSTS
        hsts = headers.get('Strict-Transport-Security')
        if not hsts:
            findings.append({
                'type': 'no_hsts',
                'severity': 'high',
                'description': 'PCI DSS 4.1: No HSTS header (transport layer protection)',
                'recommendation': 'Implement HSTS header'
            })
            score -= 15
            checks['hsts'] = 'FAIL'
        else:
            checks['hsts'] = 'PASS'

        # PCI DSS Requirement 6.5: Secure coding - XSS protection
        if not headers.get('Content-Security-Policy') and not headers.get('X-XSS-Protection'):
            findings.append({
                'type': 'no_xss_protection',
                'severity': 'high',
                'description': 'PCI DSS 6.5.7: No XSS protection headers (CSP or X-XSS-Protection)',
                'recommendation': 'Implement Content-Security-Policy header'
            })
            score -= 10
            checks['xss_protection'] = 'FAIL'
        else:
            checks['xss_protection'] = 'PASS'

        # Clickjacking protection
        if not headers.get('X-Frame-Options') and 'frame-ancestors' not in headers.get('Content-Security-Policy', ''):
            findings.append({
                'type': 'no_clickjack_protection',
                'severity': 'medium',
                'description': 'PCI DSS 6.5.9: No clickjacking protection',
                'recommendation': 'Add X-Frame-Options or CSP frame-ancestors'
            })
            score -= 10
            checks['clickjacking'] = 'FAIL'
        else:
            checks['clickjacking'] = 'PASS'

        # Server info disclosure
        server = headers.get('Server', '')
        powered = headers.get('X-Powered-By', '')
        if server or powered:
            import re
            if re.search(r'[\d.]+', server + powered):
                findings.append({
                    'type': 'server_disclosure',
                    'severity': 'medium',
                    'description': 'PCI DSS 6.5.6: Server version information disclosed',
                    'recommendation': 'Remove version information from server headers'
                })
                score -= 10
                checks['server_disclosure'] = 'FAIL'
            else:
                checks['server_disclosure'] = 'PARTIAL'
        else:
            checks['server_disclosure'] = 'PASS'

        # Cookie security for session management (PCI DSS 6.5.10)
        cookies = self.response.cookies
        for cookie in cookies:
            if not cookie.secure:
                findings.append({
                    'type': 'insecure_cookie_pci',
                    'severity': 'high',
                    'description': f"PCI DSS 6.5.10: Cookie '{cookie.name}' without Secure flag",
                    'recommendation': 'Set Secure flag on all cookies'
                })
                score -= 5
                checks['cookie_security'] = 'FAIL'

        if 'cookie_security' not in checks:
            checks['cookie_security'] = 'PASS'

        # Content-Type-Options
        if not headers.get('X-Content-Type-Options'):
            findings.append({
                'type': 'no_content_type_options',
                'severity': 'low',
                'description': 'PCI DSS 6.5: Missing X-Content-Type-Options header',
                'recommendation': 'Add X-Content-Type-Options: nosniff'
            })
            score -= 5
            checks['content_type_options'] = 'FAIL'
        else:
            checks['content_type_options'] = 'PASS'

        score = max(0, score)
        grade = self._score_to_grade(score)

        pass_count = sum(1 for v in checks.values() if v == 'PASS')
        total = len(checks)

        return {
            'module': 'PCI DSS Compliance',
            'grade': grade,
            'score': score,
            'checks': checks,
            'passed': pass_count,
            'total': total,
            'findings': findings
        }

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
