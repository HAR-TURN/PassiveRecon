"""
OWASP Top 10 Passive Checks Module
"""

import re
from bs4 import BeautifulSoup


class OWASPCheckModule:
    """Passive checks for OWASP Top 10 indicators."""

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
        soup = BeautifulSoup(body, 'html.parser')

        # A01:2021 - Broken Access Control
        a01 = self._check_broken_access(headers, body, soup)
        findings.extend(a01)
        score -= len(a01) * 5

        # A02:2021 - Cryptographic Failures
        a02 = self._check_crypto_failures(headers)
        findings.extend(a02)
        score -= len(a02) * 7

        # A03:2021 - Injection (passive indicators)
        a03 = self._check_injection_indicators(body, soup)
        findings.extend(a03)
        score -= len(a03) * 3

        # A04:2021 - Insecure Design (passive indicators)
        a04 = self._check_insecure_design(body, soup)
        findings.extend(a04)
        score -= len(a04) * 3

        # A05:2021 - Security Misconfiguration
        a05 = self._check_misconfig(headers, body)
        findings.extend(a05)
        score -= len(a05) * 5

        # A06:2021 - Vulnerable and Outdated Components
        a06 = self._check_outdated_components(body, soup)
        findings.extend(a06)
        score -= len(a06) * 5

        # A07:2021 - Identification and Authentication Failures
        a07 = self._check_auth_failures(body, soup, headers)
        findings.extend(a07)
        score -= len(a07) * 5

        # A08:2021 - Software and Data Integrity Failures
        a08 = self._check_integrity(body, soup)
        findings.extend(a08)
        score -= len(a08) * 3

        # A09:2021 - Security Logging and Monitoring Failures (limited passive)
        # A10:2021 - Server-Side Request Forgery (limited passive)

        score = max(0, score)
        grade = self._score_to_grade(score)

        return {
            'module': 'OWASP Top 10',
            'grade': grade,
            'score': score,
            'findings': findings
        }

    def _check_broken_access(self, headers, body, soup):
        findings = []

        # CORS misconfiguration
        acao = headers.get('Access-Control-Allow-Origin', '')
        if acao == '*':
            findings.append({
                'type': 'owasp_a01',
                'severity': 'high',
                'description': 'A01: CORS allows all origins (Access-Control-Allow-Origin: *)',
                'recommendation': 'Restrict CORS to specific trusted domains'
            })

        acac = headers.get('Access-Control-Allow-Credentials', '')
        if acac.lower() == 'true' and acao == '*':
            findings.append({
                'type': 'owasp_a01',
                'severity': 'critical',
                'description': 'A01: CORS allows credentials with wildcard origin',
                'recommendation': 'Never use Allow-Credentials with wildcard origin'
            })

        # Directory listing
        if re.search(r'Index of /|Directory listing|Parent Directory', body, re.IGNORECASE):
            findings.append({
                'type': 'owasp_a01',
                'severity': 'medium',
                'description': 'A01: Directory listing may be enabled',
                'recommendation': 'Disable directory listing'
            })

        return findings

    def _check_crypto_failures(self, headers):
        findings = []

        if self.parsed_url['scheme'] != 'https':
            findings.append({
                'type': 'owasp_a02',
                'severity': 'critical',
                'description': 'A02: No HTTPS - data transmitted in plaintext',
                'recommendation': 'Enable HTTPS'
            })

        if not headers.get('Strict-Transport-Security'):
            findings.append({
                'type': 'owasp_a02',
                'severity': 'high',
                'description': 'A02: No HSTS - vulnerable to SSL stripping',
                'recommendation': 'Implement HSTS'
            })

        return findings

    def _check_injection_indicators(self, body, soup):
        findings = []

        # Check forms without CSRF tokens
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            if method == 'post':
                csrf_found = False
                for inp in form.find_all('input', type='hidden'):
                    name = inp.get('name', '').lower()
                    if any(t in name for t in ['csrf', 'token', '_token', 'nonce', 'authenticity']):
                        csrf_found = True
                        break
                if not csrf_found:
                    findings.append({
                        'type': 'owasp_a03',
                        'severity': 'medium',
                        'description': f'A03: Form (action={action}) may lack CSRF protection',
                        'recommendation': 'Add CSRF tokens to all POST forms'
                    })

        # Check for inline event handlers (XSS surface)
        inline_events = soup.find_all(True, attrs=lambda attrs: attrs and
                                       any(a.startswith('on') for a in attrs))
        if len(inline_events) > 5:
            findings.append({
                'type': 'owasp_a03',
                'severity': 'low',
                'description': f'A03: {len(inline_events)} inline event handlers found (XSS surface)',
                'recommendation': 'Move event handlers to external JavaScript files'
            })

        return findings

    def _check_insecure_design(self, body, soup):
        findings = []

        # Check for autocomplete on sensitive fields
        password_fields = soup.find_all('input', type='password')
        for field in password_fields:
            if field.get('autocomplete') not in ['off', 'new-password']:
                findings.append({
                    'type': 'owasp_a04',
                    'severity': 'low',
                    'description': 'A04: Password field without autocomplete="off"',
                    'recommendation': 'Add autocomplete="off" or autocomplete="new-password" to password fields'
                })
                break

        return findings

    def _check_misconfig(self, headers, body):
        findings = []

        # Debug mode indicators
        if re.search(r'(?i)(debug\s*=\s*true|debug.?mode|development.?mode|DJANGO_DEBUG)', body):
            findings.append({
                'type': 'owasp_a05',
                'severity': 'high',
                'description': 'A05: Application may be running in debug mode',
                'recommendation': 'Disable debug mode in production'
            })

        # Default credentials in HTML
        if re.search(r'(?i)(default.?password|admin/admin|root/root|test/test)', body):
            findings.append({
                'type': 'owasp_a05',
                'severity': 'high',
                'description': 'A05: Possible default credentials reference found',
                'recommendation': 'Remove default credential references'
            })

        # Missing security headers count
        missing = 0
        for h in ['X-Content-Type-Options', 'X-Frame-Options', 'Content-Security-Policy']:
            if not headers.get(h):
                missing += 1
        if missing >= 2:
            findings.append({
                'type': 'owasp_a05',
                'severity': 'medium',
                'description': f'A05: {missing} important security headers missing',
                'recommendation': 'Implement all recommended security headers'
            })

        return findings

    def _check_outdated_components(self, body, soup):
        findings = []

        # Check for known vulnerable jQuery versions
        jquery_match = re.search(r'jquery[.-]?([\d]+\.[\d]+\.[\d]+)', body, re.IGNORECASE)
        if jquery_match:
            version = jquery_match.group(1)
            parts = version.split('.')
            if len(parts) >= 2:
                major, minor = int(parts[0]), int(parts[1])
                if major < 3 or (major == 3 and minor < 5):
                    findings.append({
                        'type': 'owasp_a06',
                        'severity': 'medium',
                        'description': f'A06: Potentially outdated jQuery version: {version}',
                        'recommendation': 'Update jQuery to the latest version (3.7+)'
                    })

        # Check for old Bootstrap
        bootstrap_match = re.search(r'bootstrap[.-]?([\d]+\.[\d]+\.[\d]+)', body, re.IGNORECASE)
        if bootstrap_match:
            version = bootstrap_match.group(1)
            major = int(version.split('.')[0])
            if major < 5:
                findings.append({
                    'type': 'owasp_a06',
                    'severity': 'low',
                    'description': f'A06: Older Bootstrap version: {version}',
                    'recommendation': 'Consider updating to Bootstrap 5.x'
                })

        return findings

    def _check_auth_failures(self, body, soup, headers):
        findings = []

        # Check login forms
        login_forms = soup.find_all('form')
        for form in login_forms:
            has_password = form.find('input', type='password')
            if has_password:
                # Check if action is HTTPS
                action = form.get('action', '')
                if action.startswith('http://'):
                    findings.append({
                        'type': 'owasp_a07',
                        'severity': 'critical',
                        'description': 'A07: Login form submits over HTTP (not HTTPS)',
                        'recommendation': 'Ensure login forms submit over HTTPS'
                    })

        return findings

    def _check_integrity(self, body, soup):
        findings = []

        # Check for scripts without SRI (Subresource Integrity)
        external_scripts = soup.find_all('script', src=True)
        for script in external_scripts:
            src = script.get('src', '')
            if src.startswith('http') or src.startswith('//'):
                if not script.get('integrity'):
                    findings.append({
                        'type': 'owasp_a08',
                        'severity': 'medium',
                        'description': f'A08: External script without SRI: {src[:80]}',
                        'recommendation': 'Add integrity attribute (SRI) to external scripts'
                    })
                    break  # Only report once

        return findings

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
