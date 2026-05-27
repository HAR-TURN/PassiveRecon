"""
JavaScript File Analyzer Module
Scans JS files for leaked secrets and sensitive information.
"""

import re
from bs4 import BeautifulSoup


class JSAnalyzerModule:
    """Analyzes JavaScript files for secrets and sensitive information."""

    SECRET_PATTERNS = {
        'AWS Key': r'AKIA[0-9A-Z]{16}',
        'Google API': r'AIza[0-9A-Za-z\-_]{35}',
        'Firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
        'Slack Token': r'xox[baprs]-[0-9a-zA-Z]{10,48}',
        'GitHub Token': r'gh[ps]_[A-Za-z0-9_]{36}',
        'Stripe Key': r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}',
        'Private Key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
        'JWT': r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+',
        'API Endpoint': r'(?:https?://)[a-zA-Z0-9\-.]+/api/[a-zA-Z0-9/_-]+',
        'Internal URL': r'(?:https?://)?(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?[/\w.-]*',
        'Hardcoded Password': r'''(?i)(?:password|passwd|pwd|secret)\s*[:=]\s*['"][^'"]{4,}['"]''',
        'Connection String': r'(?i)(?:mongodb|mysql|postgres|redis|amqp)://[^\s"\']+',
        'SendGrid': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
        'Twilio': r'SK[0-9a-fA-F]{32}',
        'Mailgun': r'key-[0-9a-zA-Z]{32}',
        'API Key Generic': r'''(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['"]([a-zA-Z0-9\-_]{20,})['"]''',
    }

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

        # Collect JS URLs
        js_urls = []
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src.startswith('//'):
                src = 'https:' + src
            elif src.startswith('/'):
                src = self.parsed_url['base_url'] + src
            elif not src.startswith('http'):
                src = self.parsed_url['base_url'] + '/' + src
            js_urls.append(src)

        # Also check inline scripts
        inline_scripts = []
        for script in soup.find_all('script'):
            if script.string:
                inline_scripts.append(script.string)

        # Analyze inline scripts
        all_secrets = {}
        inline_text = '\n'.join(inline_scripts)
        if inline_text:
            secrets = self._scan_for_secrets(inline_text)
            for stype, matches in secrets.items():
                for match in matches:
                    if stype not in all_secrets:
                        all_secrets[stype] = []
                    all_secrets[stype].append({'source': 'inline', 'match': match[:50]})

        # Analyze external JS files (limit to first 10 same-origin)
        target_domain = self.parsed_url['registered_domain']
        analyzed_js = []
        js_count = 0

        for url in js_urls[:15]:
            if target_domain and target_domain in url:
                if js_count >= 10:
                    break
                resp = self.client.get(url)
                if resp and resp.status_code == 200:
                    js_count += 1
                    secrets = self._scan_for_secrets(resp.text)
                    file_info = {'url': url, 'size': len(resp.text), 'secrets_found': []}

                    for stype, matches in secrets.items():
                        for match in matches:
                            file_info['secrets_found'].append({
                                'type': stype,
                                'match': match[:50]
                            })
                            if stype not in all_secrets:
                                all_secrets[stype] = []
                            all_secrets[stype].append({'source': url, 'match': match[:50]})

                    analyzed_js.append(file_info)

        # Generate findings
        for stype, matches in all_secrets.items():
            severity = 'critical' if stype in ['AWS Key', 'Private Key', 'Stripe Key',
                                                  'Hardcoded Password', 'Connection String'] else 'high'
            for m in matches[:3]:  # Limit per type
                findings.append({
                    'type': 'js_secret',
                    'severity': severity,
                    'description': f"Possible {stype} in JS ({m['source'][:50]}): {m['match']}",
                    'recommendation': f"Remove {stype} from client-side JavaScript"
                })
                score -= 10

        # Check for source maps
        sourcemap_patterns = [r'//# sourceMappingURL=', r'//@ sourceMappingURL=']
        for pattern in sourcemap_patterns:
            if re.search(pattern, body):
                findings.append({
                    'type': 'source_map',
                    'severity': 'medium',
                    'description': 'Source map references found (may expose source code)',
                    'recommendation': 'Remove source maps from production builds'
                })
                score -= 5
                break

        # Check for console.log statements
        console_count = len(re.findall(r'console\.(log|debug|info|warn|error)\s*\(', body))
        if console_count > 5:
            findings.append({
                'type': 'console_logs',
                'severity': 'low',
                'description': f'{console_count} console logging statements found',
                'recommendation': 'Remove console logging from production code'
            })
            score -= 3

        score = max(0, score)
        grade = self._score_to_grade(score)

        return {
            'module': 'JavaScript Analysis',
            'grade': grade,
            'score': score,
            'js_files_found': len(js_urls),
            'js_files_analyzed': len(analyzed_js),
            'inline_scripts_count': len(inline_scripts),
            'secrets_found': sum(len(v) for v in all_secrets.values()),
            'secrets_by_type': {k: len(v) for k, v in all_secrets.items()},
            'analyzed_files': analyzed_js,
            'findings': findings
        }

    def _scan_for_secrets(self, text):
        """Scan text for secrets."""
        results = {}
        for name, pattern in self.SECRET_PATTERNS.items():
            try:
                matches = re.findall(pattern, text)
                if matches:
                    clean = []
                    for m in matches:
                        if isinstance(m, tuple):
                            clean.append(m[-1] if m[-1] else m[0])
                        else:
                            clean.append(m)
                    results[name] = list(set(clean))[:3]
            except re.error:
                continue
        return results

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
