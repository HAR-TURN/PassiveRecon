"""
Robots.txt and Sitemap.xml Analysis Module
"""

import re


class RobotsSitemapModule:
    """Analyzes robots.txt and sitemap.xml."""

    def __init__(self, client, parsed_url, response, verbose=False):
        self.client = client
        self.parsed_url = parsed_url
        self.response = response
        self.verbose = verbose

    def run(self):
        findings = []
        score = 100

        base_url = self.parsed_url['base_url']

        # Fetch robots.txt
        robots_data = self._analyze_robots(base_url)
        findings.extend(robots_data.get('findings', []))
        score -= robots_data.get('penalty', 0)

        # Fetch sitemap
        sitemap_data = self._analyze_sitemap(base_url, robots_data.get('sitemaps', []))
        findings.extend(sitemap_data.get('findings', []))
        score -= sitemap_data.get('penalty', 0)

        score = max(0, score)
        grade = self._score_to_grade(score)

        return {
            'module': 'Robots & Sitemap',
            'grade': grade,
            'score': score,
            'robots': robots_data,
            'sitemap': sitemap_data,
            'findings': findings
        }

    def _analyze_robots(self, base_url):
        result = {
            'exists': False,
            'content': '',
            'disallowed': [],
            'allowed': [],
            'sitemaps': [],
            'findings': [],
            'penalty': 0,
            'sensitive_paths': []
        }

        resp = self.client.get(f"{base_url}/robots.txt")
        if not resp or resp.status_code != 200:
            result['findings'].append({
                'type': 'no_robots',
                'severity': 'low',
                'description': 'No robots.txt file found',
                'recommendation': 'Create a robots.txt file'
            })
            result['penalty'] = 5
            return result

        result['exists'] = True
        content = resp.text
        result['content'] = content[:2000]

        # Parse robots.txt
        for line in content.split('\n'):
            line = line.strip()
            if line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path:
                    result['disallowed'].append(path)
            elif line.lower().startswith('allow:'):
                path = line.split(':', 1)[1].strip()
                if path:
                    result['allowed'].append(path)
            elif line.lower().startswith('sitemap:'):
                url = line.split(':', 1)[1].strip()
                # Handle "Sitemap: http://..." properly
                if not url.startswith('http'):
                    url = 'http:' + url if url.startswith('//') else url
                result['sitemaps'].append(url)

        # Check for sensitive paths in disallow
        sensitive_patterns = [
            r'/admin', r'/backup', r'/config', r'/database', r'/debug',
            r'/dump', r'/env', r'/git', r'/log', r'/private',
            r'/secret', r'/staging', r'/test', r'/tmp', r'/upload',
            r'/api', r'/internal', r'/panel', r'/console'
        ]

        for path in result['disallowed']:
            for pattern in sensitive_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    result['sensitive_paths'].append(path)
                    break

        if result['sensitive_paths']:
            result['findings'].append({
                'type': 'sensitive_in_robots',
                'severity': 'medium',
                'description': f"Sensitive paths revealed in robots.txt: {', '.join(result['sensitive_paths'][:5])}",
                'recommendation': 'Sensitive paths in robots.txt can guide attackers. Consider restricting by other means.'
            })
            result['penalty'] += 5

        # Check if robots.txt disallows everything
        if '/' in result['disallowed'] and len(result['disallowed']) == 1:
            result['findings'].append({
                'type': 'robots_disallow_all',
                'severity': 'info',
                'description': 'robots.txt disallows all crawling',
                'recommendation': 'This prevents search engine indexing'
            })

        return result

    def _analyze_sitemap(self, base_url, robots_sitemaps):
        result = {
            'exists': False,
            'url': '',
            'entries_count': 0,
            'findings': [],
            'penalty': 0
        }

        sitemap_urls = robots_sitemaps or [f"{base_url}/sitemap.xml"]

        for sitemap_url in sitemap_urls[:3]:
            resp = self.client.get(sitemap_url)
            if resp and resp.status_code == 200:
                result['exists'] = True
                result['url'] = sitemap_url

                # Count URLs in sitemap
                url_count = len(re.findall(r'<loc>', resp.text))
                result['entries_count'] = url_count

                # Check for sensitive URLs in sitemap
                sensitive = re.findall(r'<loc>([^<]*(?:admin|config|debug|test|staging|internal)[^<]*)</loc>',
                                       resp.text, re.IGNORECASE)
                if sensitive:
                    result['findings'].append({
                        'type': 'sensitive_in_sitemap',
                        'severity': 'medium',
                        'description': f'Sensitive URLs found in sitemap: {", ".join(sensitive[:3])}',
                        'recommendation': 'Remove sensitive URLs from sitemap'
                    })
                    result['penalty'] += 5

                break

        if not result['exists']:
            result['findings'].append({
                'type': 'no_sitemap',
                'severity': 'info',
                'description': 'No sitemap.xml found',
                'recommendation': 'Create a sitemap.xml for better SEO and crawling'
            })

        return result

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
