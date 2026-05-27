"""
Cookie Privacy and Security Analyzer Module
"""


class CookieAnalyzerModule:
    """Analyzes cookies for security and privacy flags."""

    def __init__(self, client, parsed_url, response, verbose=False):
        self.client = client
        self.parsed_url = parsed_url
        self.response = response
        self.verbose = verbose

    def run(self):
        findings = []
        cookies_analysis = []
        score = 100

        cookies = self.response.cookies
        set_cookie_headers = self.response.headers.get('Set-Cookie', '')

        # Also get raw Set-Cookie headers
        raw_cookies = []
        for key, value in self.response.headers.items():
            if key.lower() == 'set-cookie':
                raw_cookies.append(value)

        if not cookies and not raw_cookies:
            return {
                'module': 'Cookie Security',
                'grade': 'A',
                'score': 100,
                'cookies_found': 0,
                'cookies': [],
                'findings': [{
                    'type': 'info',
                    'severity': 'info',
                    'description': 'No cookies set by the server',
                    'recommendation': 'N/A'
                }]
            }

        # Analyze each cookie
        for cookie in cookies:
            cookie_data = self._analyze_cookie(cookie, cookies)
            cookies_analysis.append(cookie_data)

            # Check security flags
            if not cookie_data.get('secure'):
                findings.append({
                    'type': 'insecure_cookie',
                    'severity': 'high',
                    'description': f"Cookie '{cookie.name}' missing Secure flag",
                    'recommendation': f"Add Secure flag to cookie '{cookie.name}'"
                })
                score -= 10

            if not cookie_data.get('httponly'):
                # Check if it's a session cookie
                session_indicators = ['session', 'sid', 'token', 'auth', 'jwt', 'csrf']
                is_session = any(ind in cookie.name.lower() for ind in session_indicators)
                if is_session:
                    findings.append({
                        'type': 'no_httponly',
                        'severity': 'high',
                        'description': f"Session cookie '{cookie.name}' missing HttpOnly flag (vulnerable to XSS cookie theft)",
                        'recommendation': f"Add HttpOnly flag to cookie '{cookie.name}'"
                    })
                    score -= 15
                else:
                    findings.append({
                        'type': 'no_httponly',
                        'severity': 'medium',
                        'description': f"Cookie '{cookie.name}' missing HttpOnly flag",
                        'recommendation': f"Add HttpOnly flag to cookie '{cookie.name}'"
                    })
                    score -= 5

            if not cookie_data.get('samesite'):
                findings.append({
                    'type': 'no_samesite',
                    'severity': 'medium',
                    'description': f"Cookie '{cookie.name}' missing SameSite attribute",
                    'recommendation': f"Add SameSite=Strict or SameSite=Lax to cookie '{cookie.name}'"
                })
                score -= 5
            elif cookie_data.get('samesite', '').lower() == 'none':
                findings.append({
                    'type': 'samesite_none',
                    'severity': 'medium',
                    'description': f"Cookie '{cookie.name}' has SameSite=None (sent with cross-site requests)",
                    'recommendation': f"Use SameSite=Strict or SameSite=Lax unless cross-site is required"
                })
                score -= 3

            # Check for sensitive-looking cookie names without proper flags
            sensitive_names = ['password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey', 'private']
            for sn in sensitive_names:
                if sn in cookie.name.lower():
                    findings.append({
                        'type': 'sensitive_cookie_name',
                        'severity': 'high',
                        'description': f"Cookie name '{cookie.name}' suggests sensitive data in cookie",
                        'recommendation': 'Avoid storing sensitive data in cookies'
                    })
                    score -= 10
                    break

        score = max(0, score)
        grade = self._score_to_grade(score)

        return {
            'module': 'Cookie Security',
            'grade': grade,
            'score': score,
            'cookies_found': len(cookies_analysis),
            'cookies': cookies_analysis,
            'findings': findings
        }

    def _analyze_cookie(self, cookie, jar):
        """Analyze individual cookie properties."""
        return {
            'name': cookie.name,
            'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
            'domain': cookie.domain,
            'path': cookie.path,
            'secure': cookie.secure,
            'httponly': cookie.has_nonstandard_attr('HttpOnly') or cookie.has_nonstandard_attr('httponly'),
            'samesite': cookie.get_nonstandard_attr('SameSite') or cookie.get_nonstandard_attr('samesite'),
            'expires': str(cookie.expires) if cookie.expires else 'Session',
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
