"""
Content Security Policy (CSP) Analyzer Module
"""

import re


class CSPAnalyzerModule:
    """Analyzes Content Security Policy headers."""

    DANGEROUS_SOURCES = ["'unsafe-inline'", "'unsafe-eval'", "data:", "blob:", "*"]

    IMPORTANT_DIRECTIVES = [
        'default-src', 'script-src', 'style-src', 'img-src',
        'connect-src', 'font-src', 'object-src', 'media-src',
        'frame-src', 'frame-ancestors', 'form-action', 'base-uri',
        'upgrade-insecure-requests', 'block-all-mixed-content'
    ]

    def __init__(self, client, parsed_url, response, verbose=False):
        self.client = client
        self.parsed_url = parsed_url
        self.response = response
        self.verbose = verbose

    def run(self):
        findings = []
        score = 100

        csp_header = self.response.headers.get('Content-Security-Policy', '')
        csp_report = self.response.headers.get('Content-Security-Policy-Report-Only', '')

        if not csp_header and not csp_report:
            findings.append({
                'type': 'missing_csp',
                'severity': 'high',
                'description': 'No Content-Security-Policy header found',
                'recommendation': 'Implement a Content-Security-Policy header'
            })
            return {
                'module': 'Content Security Policy',
                'grade': 'F',
                'score': 20,
                'csp_present': False,
                'csp_report_only': bool(csp_report),
                'directives': {},
                'findings': findings
            }

        if not csp_header and csp_report:
            findings.append({
                'type': 'csp_report_only',
                'severity': 'medium',
                'description': 'CSP is in report-only mode (not enforced)',
                'recommendation': 'Switch from Content-Security-Policy-Report-Only to Content-Security-Policy'
            })
            score -= 15
            csp_to_parse = csp_report
        else:
            csp_to_parse = csp_header

        # Parse CSP directives
        directives = self._parse_csp(csp_to_parse)

        # Analyze directives
        # Check for default-src
        if 'default-src' not in directives:
            findings.append({
                'type': 'missing_directive',
                'severity': 'medium',
                'description': 'Missing default-src directive',
                'recommendation': "Add default-src 'self' as a fallback"
            })
            score -= 10

        # Check for unsafe sources
        for directive, values in directives.items():
            for dangerous in self.DANGEROUS_SOURCES:
                if dangerous in values:
                    if dangerous == "'unsafe-inline'" and directive in ['script-src', 'default-src']:
                        findings.append({
                            'type': 'unsafe_csp',
                            'severity': 'high',
                            'description': f"'unsafe-inline' found in {directive} (allows inline scripts/XSS)",
                            'recommendation': f"Remove 'unsafe-inline' from {directive} and use nonces or hashes"
                        })
                        score -= 15
                    elif dangerous == "'unsafe-eval'" and directive in ['script-src', 'default-src']:
                        findings.append({
                            'type': 'unsafe_csp',
                            'severity': 'high',
                            'description': f"'unsafe-eval' found in {directive} (allows eval())",
                            'recommendation': f"Remove 'unsafe-eval' from {directive}"
                        })
                        score -= 15
                    elif dangerous == '*':
                        findings.append({
                            'type': 'wildcard_csp',
                            'severity': 'high',
                            'description': f"Wildcard '*' found in {directive}",
                            'recommendation': f"Replace wildcard with specific domains in {directive}"
                        })
                        score -= 10
                    elif dangerous == 'data:' and directive in ['script-src', 'default-src']:
                        findings.append({
                            'type': 'unsafe_csp',
                            'severity': 'medium',
                            'description': f"'data:' URI scheme in {directive}",
                            'recommendation': f"Remove 'data:' from {directive} if possible"
                        })
                        score -= 5

        # Check for frame-ancestors
        if 'frame-ancestors' not in directives:
            findings.append({
                'type': 'missing_directive',
                'severity': 'medium',
                'description': 'Missing frame-ancestors directive (clickjacking protection)',
                'recommendation': "Add frame-ancestors 'self' or 'none'"
            })
            score -= 5

        # Check for object-src
        if 'object-src' not in directives and \
           directives.get('default-src', [''])[0] != "'none'":
            findings.append({
                'type': 'missing_directive',
                'severity': 'medium',
                'description': "Missing object-src directive (Flash/Java plugin protection)",
                'recommendation': "Add object-src 'none'"
            })
            score -= 5

        # Check for base-uri
        if 'base-uri' not in directives:
            findings.append({
                'type': 'missing_directive',
                'severity': 'low',
                'description': 'Missing base-uri directive',
                'recommendation': "Add base-uri 'self'"
            })
            score -= 3

        # Check for form-action
        if 'form-action' not in directives:
            findings.append({
                'type': 'missing_directive',
                'severity': 'low',
                'description': 'Missing form-action directive',
                'recommendation': "Add form-action 'self'"
            })
            score -= 3

        score = max(0, score)
        grade = self._score_to_grade(score)

        return {
            'module': 'Content Security Policy',
            'grade': grade,
            'score': score,
            'csp_present': bool(csp_header),
            'csp_report_only': bool(csp_report),
            'raw_csp': csp_to_parse,
            'directives': directives,
            'findings': findings
        }

    def _parse_csp(self, csp_string):
        """Parse CSP header into directives dict."""
        directives = {}
        parts = csp_string.split(';')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            tokens = part.split()
            if tokens:
                directive_name = tokens[0].lower()
                directive_values = tokens[1:] if len(tokens) > 1 else []
                directives[directive_name] = directive_values
        return directives

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
