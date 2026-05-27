"""
HTTP Header Security Analysis Module
"""


class HeaderSecurityModule:
    """Analyzes HTTP security headers."""

    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'description': 'HTTP Strict Transport Security (HSTS)',
            'severity': 'high',
            'recommendation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
        },
        'X-Frame-Options': {
            'description': 'Clickjacking Protection',
            'severity': 'medium',
            'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'description': 'MIME-type Sniffing Protection',
            'severity': 'medium',
            'recommendation': 'Add X-Content-Type-Options: nosniff'
        },
        'X-XSS-Protection': {
            'description': 'XSS Filter (Legacy)',
            'severity': 'low',
            'recommendation': 'Add X-XSS-Protection: 1; mode=block (or rely on CSP)'
        },
        'Content-Security-Policy': {
            'description': 'Content Security Policy',
            'severity': 'high',
            'recommendation': 'Implement a strict Content-Security-Policy header'
        },
        'Referrer-Policy': {
            'description': 'Referrer Information Control',
            'severity': 'medium',
            'recommendation': 'Add Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'description': 'Browser Feature Permissions',
            'severity': 'medium',
            'recommendation': 'Add Permissions-Policy to restrict browser features'
        },
        'X-Permitted-Cross-Domain-Policies': {
            'description': 'Adobe Cross-Domain Policy',
            'severity': 'low',
            'recommendation': 'Add X-Permitted-Cross-Domain-Policies: none'
        },
        'Cross-Origin-Embedder-Policy': {
            'description': 'Cross-Origin Embedder Policy',
            'severity': 'low',
            'recommendation': 'Add Cross-Origin-Embedder-Policy: require-corp'
        },
        'Cross-Origin-Opener-Policy': {
            'description': 'Cross-Origin Opener Policy',
            'severity': 'low',
            'recommendation': 'Add Cross-Origin-Opener-Policy: same-origin'
        },
        'Cross-Origin-Resource-Policy': {
            'description': 'Cross-Origin Resource Policy',
            'severity': 'low',
            'recommendation': 'Add Cross-Origin-Resource-Policy: same-origin'
        },
    }

    INFORMATION_HEADERS = [
        'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
        'X-Generator', 'X-Drupal-Cache', 'X-Varnish', 'Via',
        'X-Runtime', 'X-Version', 'X-Backend-Server'
    ]

    def __init__(self, client, parsed_url, response, verbose=False):
        self.client = client
        self.parsed_url = parsed_url
        self.response = response
        self.verbose = verbose

    def run(self):
        """Run header security analysis."""
        findings = []
        headers_present = {}
        headers_missing = {}
        info_leaks = {}

        headers = self.response.headers

        # Check security headers
        score = 100
        for header, info in self.SECURITY_HEADERS.items():
            header_value = headers.get(header)
            if header_value:
                headers_present[header] = {
                    'value': header_value,
                    'description': info['description']
                }
                # Validate header values
                issues = self._validate_header(header, header_value)
                for issue in issues:
                    findings.append(issue)
                    score -= 3
            else:
                headers_missing[header] = info
                findings.append({
                    'type': 'missing_header',
                    'header': header,
                    'severity': info['severity'],
                    'description': f"Missing {info['description']} header",
                    'recommendation': info['recommendation']
                })
                severity_penalty = {'high': 10, 'medium': 7, 'low': 3}
                score -= severity_penalty.get(info['severity'], 5)

        # Check for information disclosure headers
        for header in self.INFORMATION_HEADERS:
            header_value = headers.get(header)
            if header_value:
                info_leaks[header] = header_value
                findings.append({
                    'type': 'info_disclosure',
                    'header': header,
                    'value': header_value,
                    'severity': 'medium',
                    'description': f"Information disclosure via {header} header: {header_value}",
                    'recommendation': f"Remove or obscure the {header} header"
                })
                score -= 5

        # Determine grade
        score = max(0, score)
        grade = self._score_to_grade(score)

        return {
            'module': 'HTTP Header Security',
            'grade': grade,
            'score': score,
            'headers_present': headers_present,
            'headers_missing': headers_missing,
            'information_disclosure': info_leaks,
            'findings': findings,
            'all_headers': dict(headers)
        }

    def _validate_header(self, header, value):
        """Validate specific header values."""
        issues = []

        if header == 'Strict-Transport-Security':
            if 'max-age' not in value.lower():
                issues.append({
                    'type': 'weak_header',
                    'header': header,
                    'value': value,
                    'severity': 'medium',
                    'description': 'HSTS missing max-age directive',
                    'recommendation': 'Add max-age=31536000 to HSTS header'
                })
            else:
                import re
                match = re.search(r'max-age=(\d+)', value)
                if match and int(match.group(1)) < 15768000:
                    issues.append({
                        'type': 'weak_header',
                        'header': header,
                        'value': value,
                        'severity': 'low',
                        'description': 'HSTS max-age is less than 6 months',
                        'recommendation': 'Set max-age to at least 31536000 (1 year)'
                    })

            if 'includesubdomains' not in value.lower():
                issues.append({
                    'type': 'weak_header',
                    'header': header,
                    'value': value,
                    'severity': 'low',
                    'description': 'HSTS missing includeSubDomains',
                    'recommendation': 'Add includeSubDomains to HSTS header'
                })

        elif header == 'X-Frame-Options':
            val = value.upper()
            if val not in ['DENY', 'SAMEORIGIN'] and not val.startswith('ALLOW-FROM'):
                issues.append({
                    'type': 'weak_header',
                    'header': header,
                    'value': value,
                    'severity': 'medium',
                    'description': f'Invalid X-Frame-Options value: {value}',
                    'recommendation': 'Set to DENY or SAMEORIGIN'
                })

        elif header == 'X-Content-Type-Options':
            if value.lower() != 'nosniff':
                issues.append({
                    'type': 'weak_header',
                    'header': header,
                    'value': value,
                    'severity': 'low',
                    'description': f'X-Content-Type-Options should be "nosniff", got "{value}"',
                    'recommendation': 'Set to nosniff'
                })

        return issues

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
