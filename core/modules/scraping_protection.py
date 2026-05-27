"""
Data Scraping Protection Check Module
"""

import re


class ScrapingProtectionModule:
    """Checks for protections against data scraping."""

    def __init__(self, client, parsed_url, response, verbose=False):
        self.client = client
        self.parsed_url = parsed_url
        self.response = response
        self.verbose = verbose

    def run(self):
        findings = []
        score = 100
        protections = {}

        headers = self.response.headers
        body = self.response.text

        # Rate limiting headers
        rate_limit_headers = ['X-RateLimit-Limit', 'X-RateLimit-Remaining',
                              'X-Rate-Limit-Limit', 'Retry-After',
                              'X-RateLimit-Reset', 'RateLimit-Limit']
        rate_limiting = any(headers.get(h) for h in rate_limit_headers)
        protections['rate_limiting'] = rate_limiting
        if not rate_limiting:
            findings.append({
                'type': 'no_rate_limit',
                'severity': 'medium',
                'description': 'No rate limiting headers detected',
                'recommendation': 'Implement rate limiting to prevent scraping'
            })
            score -= 10

        # CAPTCHA detection
        captcha_patterns = [
            r'recaptcha', r'hcaptcha', r'captcha', r'turnstile',
            r'g-recaptcha', r'h-captcha', r'cf-turnstile'
        ]
        has_captcha = any(re.search(p, body, re.IGNORECASE) for p in captcha_patterns)
        protections['captcha'] = has_captcha

        # Bot detection
        bot_detection_patterns = [
            r'bot.?detect', r'fingerprint', r'device.?fingerprint',
            r'datadome', r'distil', r'perimeterx', r'kasada',
            r'akamai.?bot', r'cloudflare.?challenge', r'shield.?square'
        ]
        has_bot_detection = any(re.search(p, body, re.IGNORECASE) for p in bot_detection_patterns)
        protections['bot_detection'] = has_bot_detection

        # WAF detection
        waf_indicators = {
            'Cloudflare': headers.get('cf-ray') or 'cloudflare' in headers.get('server', '').lower(),
            'AWS WAF': bool(headers.get('x-amzn-requestid')),
            'Akamai': bool(headers.get('x-akamai-transformed')),
            'Incapsula': bool(headers.get('X-CDN', '') == 'Imperva'),
            'Sucuri': 'sucuri' in headers.get('server', '').lower(),
            'ModSecurity': bool(headers.get('X-Mod-Security')),
        }
        active_wafs = [name for name, detected in waf_indicators.items() if detected]
        protections['waf'] = active_wafs

        # Anti-scraping meta tags
        meta_robots = None
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(body, 'html.parser')
        robots_meta = soup.find('meta', attrs={'name': re.compile(r'robots', re.IGNORECASE)})
        if robots_meta:
            meta_robots = robots_meta.get('content', '')
            protections['meta_robots'] = meta_robots

        # Check for honeypot fields
        honeypots = soup.find_all(['input', 'div'], style=re.compile(r'display\s*:\s*none|visibility\s*:\s*hidden'))
        protections['honeypot_fields'] = len(honeypots)

        # Content obfuscation
        obfuscation_patterns = [
            r'data:text/html', r'document\.write\(', r'eval\(unescape',
            r'String\.fromCharCode'
        ]
        has_obfuscation = any(re.search(p, body) for p in obfuscation_patterns)
        protections['content_obfuscation'] = has_obfuscation

        # Summary
        protection_count = sum([
            rate_limiting, has_captcha, has_bot_detection,
            len(active_wafs) > 0, has_obfuscation,
            protections.get('honeypot_fields', 0) > 0
        ])

        if protection_count == 0:
            findings.append({
                'type': 'no_scraping_protection',
                'severity': 'medium',
                'description': 'No scraping protection mechanisms detected',
                'recommendation': 'Implement rate limiting, CAPTCHA, or WAF'
            })
            score -= 15
        elif protection_count < 2:
            findings.append({
                'type': 'minimal_protection',
                'severity': 'low',
                'description': 'Minimal scraping protection detected',
                'recommendation': 'Consider adding additional layers of protection'
            })
            score -= 5

        score = max(0, score)
        grade = self._score_to_grade(score)

        return {
            'module': 'Scraping Protection',
            'grade': grade,
            'score': score,
            'protections': protections,
            'protection_count': protection_count,
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
