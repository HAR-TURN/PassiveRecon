"""
External Content Security Module
"""

import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup


class ExternalContentModule:
    """Analyzes external content and third-party resources."""

    def __init__(self, client, parsed_url, response, verbose=False):
        self.client = client
        self.parsed_url = parsed_url
        self.response = response
        self.verbose = verbose

    def run(self):
        findings = []
        score = 100

        body = self.response.text
        soup = BeautifulSoup(body, 'html.parser')
        target_domain = self.parsed_url['registered_domain']

        external_resources = {
            'scripts': [],
            'stylesheets': [],
            'images': [],
            'iframes': [],
            'fonts': [],
            'other': []
        }

        # Analyze script tags
        for tag in soup.find_all('script', src=True):
            src = tag['src']
            if self._is_external(src, target_domain):
                has_sri = bool(tag.get('integrity'))
                external_resources['scripts'].append({
                    'url': src,
                    'integrity': has_sri,
                    'crossorigin': tag.get('crossorigin', '')
                })

        # Analyze stylesheets
        for tag in soup.find_all('link', rel='stylesheet'):
            href = tag.get('href', '')
            if href and self._is_external(href, target_domain):
                has_sri = bool(tag.get('integrity'))
                external_resources['stylesheets'].append({
                    'url': href,
                    'integrity': has_sri
                })

        # Analyze iframes
        for tag in soup.find_all('iframe'):
            src = tag.get('src', '')
            if src and self._is_external(src, target_domain):
                external_resources['iframes'].append({
                    'url': src,
                    'sandbox': tag.get('sandbox', ''),
                    'allow': tag.get('allow', '')
                })

        # Analyze images
        for tag in soup.find_all('img', src=True):
            src = tag['src']
            if self._is_external(src, target_domain):
                external_resources['images'].append({'url': src})

        # Check for external fonts
        font_pattern = re.findall(r'(?:fonts\.googleapis\.com|fonts\.gstatic\.com|use\.typekit\.net|fast\.fonts\.net)[^\s"\']+', body)
        for font_url in font_pattern:
            external_resources['fonts'].append({'url': font_url})

        # Findings
        total_external = sum(len(v) for v in external_resources.values())

        if total_external > 20:
            findings.append({
                'type': 'excessive_external',
                'severity': 'medium',
                'description': f'{total_external} external resources loaded',
                'recommendation': 'Reduce external dependencies and self-host critical resources'
            })
            score -= 10

        # Scripts without SRI
        scripts_no_sri = [s for s in external_resources['scripts'] if not s['integrity']]
        if scripts_no_sri:
            findings.append({
                'type': 'no_sri',
                'severity': 'medium',
                'description': f'{len(scripts_no_sri)} external scripts without Subresource Integrity',
                'recommendation': 'Add integrity and crossorigin attributes to external scripts'
            })
            score -= min(len(scripts_no_sri) * 3, 15)

        # Iframes without sandbox
        unsandboxed = [i for i in external_resources['iframes'] if not i['sandbox']]
        if unsandboxed:
            findings.append({
                'type': 'unsandboxed_iframe',
                'severity': 'medium',
                'description': f'{len(unsandboxed)} iframes without sandbox attribute',
                'recommendation': 'Add sandbox attribute to iframes'
            })
            score -= min(len(unsandboxed) * 5, 15)

        # Mixed content check
        if self.parsed_url['scheme'] == 'https':
            http_resources = []
            for category, items in external_resources.items():
                for item in items:
                    url = item.get('url', '')
                    if url.startswith('http://'):
                        http_resources.append(url)
            if http_resources:
                findings.append({
                    'type': 'mixed_content',
                    'severity': 'high',
                    'description': f'{len(http_resources)} HTTP resources loaded on HTTPS page (mixed content)',
                    'recommendation': 'Load all resources over HTTPS'
                })
                score -= 15

        # Collect unique external domains
        external_domains = set()
        for category, items in external_resources.items():
            for item in items:
                url = item.get('url', '')
                try:
                    parsed = urlparse(url)
                    if parsed.hostname:
                        external_domains.add(parsed.hostname)
                except Exception:
                    pass

        score = max(0, score)
        grade = self._score_to_grade(score)

        return {
            'module': 'External Content Security',
            'grade': grade,
            'score': score,
            'total_external_resources': total_external,
            'external_domains': list(external_domains),
            'external_domains_count': len(external_domains),
            'resources': external_resources,
            'findings': findings
        }

    def _is_external(self, url, target_domain):
        """Check if URL is external."""
        if not url or url.startswith('data:') or url.startswith('#'):
            return False
        if url.startswith('//') or url.startswith('http://') or url.startswith('https://'):
            try:
                parsed = urlparse(url if not url.startswith('//') else 'https:' + url)
                if parsed.hostname and target_domain not in parsed.hostname:
                    return True
            except Exception:
                pass
        return False

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
