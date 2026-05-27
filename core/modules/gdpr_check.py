"""
GDPR Compliance Indicators Module
"""

import re
from bs4 import BeautifulSoup


class GDPRCheckModule:
    """Checks for GDPR compliance indicators."""

    def __init__(self, client, parsed_url, response, verbose=False):
        self.client = client
        self.parsed_url = parsed_url
        self.response = response
        self.verbose = verbose

    def run(self):
        findings = []
        score = 100

        body = self.response.text.lower()
        soup = BeautifulSoup(self.response.text, 'html.parser')
        headers = self.response.headers

        checks = {
            'cookie_consent': False,
            'privacy_policy': False,
            'terms_of_service': False,
            'data_collection_notice': False,
            'third_party_trackers': [],
            'contact_dpo': False,
            'cookie_banner': False,
        }

        # Check for cookie consent / cookie banner
        cookie_consent_patterns = [
            r'cookie.?consent', r'cookie.?banner', r'cookie.?notice',
            r'cookiebot', r'onetrust', r'cookie.?law', r'gdpr.?consent',
            r'accept.?cookie', r'cookie.?policy', r'cookie.?popup',
            r'consent.?manager', r'cookie.?bar', r'tarteaucitron',
            r'cookieconsent', r'cc-window', r'cc-banner'
        ]
        for pattern in cookie_consent_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                checks['cookie_consent'] = True
                checks['cookie_banner'] = True
                break

        if not checks['cookie_consent']:
            findings.append({
                'type': 'no_cookie_consent',
                'severity': 'high',
                'description': 'No cookie consent mechanism detected',
                'recommendation': 'Implement a cookie consent banner/mechanism for GDPR compliance'
            })
            score -= 20

        # Check for privacy policy link
        privacy_patterns = [
            r'privacy.?policy', r'datenschutz', r'privacidad',
            r'politique.?de.?confidentialit', r'data.?protection',
            r'privacy.?notice', r'/privacy'
        ]
        for link in soup.find_all('a', href=True):
            link_text = link.get_text().lower() + ' ' + link['href'].lower()
            for pattern in privacy_patterns:
                if re.search(pattern, link_text):
                    checks['privacy_policy'] = True
                    break

        if not checks['privacy_policy']:
            findings.append({
                'type': 'no_privacy_policy',
                'severity': 'high',
                'description': 'No privacy policy link detected',
                'recommendation': 'Add a clearly visible link to your privacy policy'
            })
            score -= 15

        # Check for terms of service
        tos_patterns = [r'terms.?of.?service', r'terms.?of.?use', r'terms.?and.?conditions', r'/terms', r'/tos']
        for link in soup.find_all('a', href=True):
            link_text = link.get_text().lower() + ' ' + link['href'].lower()
            for pattern in tos_patterns:
                if re.search(pattern, link_text):
                    checks['terms_of_service'] = True
                    break

        if not checks['terms_of_service']:
            findings.append({
                'type': 'no_tos',
                'severity': 'medium',
                'description': 'No terms of service link detected',
                'recommendation': 'Add terms of service/use page'
            })
            score -= 10

        # Check for third-party trackers (GDPR relevance)
        tracker_domains = [
            'google-analytics.com', 'googletagmanager.com', 'facebook.net',
            'doubleclick.net', 'hotjar.com', 'mixpanel.com', 'segment.com',
            'amplitude.com', 'fullstory.com', 'mouseflow.com',
            'crazyegg.com', 'optimizely.com', 'hubspot.com'
        ]
        for domain in tracker_domains:
            if domain in body:
                checks['third_party_trackers'].append(domain)

        if checks['third_party_trackers'] and not checks['cookie_consent']:
            findings.append({
                'type': 'trackers_no_consent',
                'severity': 'high',
                'description': f"Third-party trackers found without cookie consent: {', '.join(checks['third_party_trackers'])}",
                'recommendation': 'Implement cookie consent before loading third-party trackers'
            })
            score -= 15

        # Check DPO / Contact info
        dpo_patterns = [r'data.?protection.?officer', r'dpo@', r'privacy@', r'gdpr@']
        for pattern in dpo_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                checks['contact_dpo'] = True
                break

        # Check P3P header (legacy privacy)
        if headers.get('P3P'):
            findings.append({
                'type': 'legacy_p3p',
                'severity': 'info',
                'description': f"Legacy P3P header found: {headers.get('P3P')}",
                'recommendation': 'P3P is deprecated; focus on modern GDPR compliance'
            })

        score = max(0, score)
        grade = self._score_to_grade(score)

        return {
            'module': 'GDPR Compliance',
            'grade': grade,
            'score': score,
            'checks': checks,
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
