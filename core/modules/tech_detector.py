"""
Technology/CMS Detection Module with Version Identification
"""

import re
from bs4 import BeautifulSoup


class TechDetectorModule:
    """Detects web technologies, CMS, frameworks, and their versions."""

    def __init__(self, client, parsed_url, response, verbose=False):
        self.client = client
        self.parsed_url = parsed_url
        self.response = response
        self.verbose = verbose

    def run(self):
        findings = []
        technologies = []

        headers = self.response.headers
        body = self.response.text
        soup = BeautifulSoup(body, 'html.parser')

        # ---- Server Detection ----
        server = headers.get('Server', '')
        if server:
            tech = {'category': 'Web Server', 'name': server.split('/')[0], 'version': '', 'raw': server}
            version_match = re.search(r'[\d]+\.[\d]+[\.\d]*', server)
            if version_match:
                tech['version'] = version_match.group()
                findings.append({
                    'type': 'version_disclosure',
                    'severity': 'medium',
                    'description': f"Server version disclosed: {server}",
                    'recommendation': 'Remove server version from response headers'
                })
            technologies.append(tech)

        # ---- X-Powered-By ----
        powered_by = headers.get('X-Powered-By', '')
        if powered_by:
            tech = {'category': 'Backend', 'name': powered_by.split('/')[0], 'version': '', 'raw': powered_by}
            version_match = re.search(r'[\d]+\.[\d]+[\.\d]*', powered_by)
            if version_match:
                tech['version'] = version_match.group()
            technologies.append(tech)
            findings.append({
                'type': 'tech_disclosure',
                'severity': 'medium',
                'description': f"Backend technology disclosed: {powered_by}",
                'recommendation': 'Remove X-Powered-By header'
            })

        # ---- CMS Detection ----
        cms_checks = self._detect_cms(body, soup, headers)
        technologies.extend(cms_checks)

        # ---- CDN / Proxy Detection ----
        cdn_checks = self._detect_cdn(headers)
        technologies.extend(cdn_checks)

        # ---- JavaScript Frameworks ----
        js_checks = self._detect_js_frameworks(body, soup)
        technologies.extend(js_checks)

        # ---- CSS Frameworks ----
        css_checks = self._detect_css_frameworks(body, soup)
        technologies.extend(css_checks)

        # ---- Analytics / Tracking ----
        analytics_checks = self._detect_analytics(body)
        technologies.extend(analytics_checks)

        # ---- Programming Languages ----
        lang_checks = self._detect_languages(headers, body)
        technologies.extend(lang_checks)

        # ---- Static vs Dynamic ----
        site_type = self._detect_site_type(headers, body, soup)

        # Version disclosure findings
        for tech in technologies:
            if tech.get('version'):
                findings.append({
                    'type': 'version_detected',
                    'severity': 'info',
                    'description': f"Detected {tech['category']}: {tech['name']} v{tech['version']}",
                    'recommendation': 'Ensure software is up to date'
                })

        score = 100
        version_disclosures = sum(1 for f in findings if f['type'] == 'version_disclosure')
        tech_disclosures = sum(1 for f in findings if f['type'] == 'tech_disclosure')
        score -= version_disclosures * 10
        score -= tech_disclosures * 5
        score = max(0, score)

        grade = self._score_to_grade(score)

        return {
            'module': 'Technology Detection',
            'grade': grade,
            'score': score,
            'site_type': site_type,
            'technologies': technologies,
            'tech_count': len(technologies),
            'findings': findings
        }

    def _detect_cms(self, body, soup, headers):
        """Detect CMS platforms."""
        cms_list = []

        # WordPress
        wp_indicators = [
            (r'wp-content/', 'WordPress', body),
            (r'wp-includes/', 'WordPress', body),
            (r'wp-json', 'WordPress', body),
            (r'<meta name="generator" content="WordPress\s*([\d.]*)"', 'WordPress', body),
        ]
        for pattern, name, text in wp_indicators:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                version = ''
                ver_match = re.search(r'WordPress\s*([\d.]+)', body, re.IGNORECASE)
                if ver_match:
                    version = ver_match.group(1)
                # Also check meta generator
                gen = soup.find('meta', attrs={'name': 'generator'})
                if gen and 'wordpress' in gen.get('content', '').lower():
                    v = re.search(r'[\d.]+', gen['content'])
                    if v:
                        version = v.group()
                cms_list.append({'category': 'CMS', 'name': 'WordPress', 'version': version, 'raw': ''})
                break

        # Joomla
        if re.search(r'/components/com_|/modules/mod_|Joomla!', body, re.IGNORECASE):
            version = ''
            gen = soup.find('meta', attrs={'name': 'generator'})
            if gen and 'joomla' in gen.get('content', '').lower():
                v = re.search(r'[\d.]+', gen['content'])
                if v:
                    version = v.group()
            cms_list.append({'category': 'CMS', 'name': 'Joomla', 'version': version, 'raw': ''})

        # Drupal
        if re.search(r'Drupal|drupal\.js|sites/all/|sites/default/', body, re.IGNORECASE) or \
           headers.get('X-Drupal-Cache') or headers.get('X-Generator', '').lower().startswith('drupal'):
            version = ''
            gen = soup.find('meta', attrs={'name': 'generator'})
            if gen and 'drupal' in gen.get('content', '').lower():
                v = re.search(r'[\d.]+', gen['content'])
                if v:
                    version = v.group()
            cms_list.append({'category': 'CMS', 'name': 'Drupal', 'version': version, 'raw': ''})

        # Shopify
        if re.search(r'cdn\.shopify\.com|Shopify\.theme|shopify-section', body, re.IGNORECASE) or \
           'shopify' in headers.get('X-ShopId', '').lower() or \
           'shopify' in headers.get('X-Sorting-Hat-ShopId', '').lower():
            cms_list.append({'category': 'E-Commerce', 'name': 'Shopify', 'version': '', 'raw': ''})

        # Wix
        if re.search(r'wix\.com|_wix_browser_sess|X-Wix-', body, re.IGNORECASE) or \
           any('wix' in v.lower() for v in headers.values()):
            cms_list.append({'category': 'Website Builder', 'name': 'Wix', 'version': '', 'raw': ''})

        # Squarespace
        if re.search(r'squarespace\.com|sqsp|static\.squarespace', body, re.IGNORECASE):
            cms_list.append({'category': 'Website Builder', 'name': 'Squarespace', 'version': '', 'raw': ''})

        # HubSpot
        if re.search(r'hs-scripts\.com|hubspot|hbspt\.forms|hs-analytics', body, re.IGNORECASE):
            cms_list.append({'category': 'Marketing/CMS', 'name': 'HubSpot', 'version': '', 'raw': ''})

        # Magento
        if re.search(r'Magento|mage-|/skin/frontend/|varien/js', body, re.IGNORECASE) or \
           'Magento' in headers.get('X-Magento-', ''):
            cms_list.append({'category': 'E-Commerce', 'name': 'Magento', 'version': '', 'raw': ''})

        # Ghost
        if re.search(r'ghost\.io|ghost-|content="Ghost"', body, re.IGNORECASE):
            cms_list.append({'category': 'CMS', 'name': 'Ghost', 'version': '', 'raw': ''})

        # PrestaShop
        if re.search(r'prestashop|/modules/ps_', body, re.IGNORECASE):
            cms_list.append({'category': 'E-Commerce', 'name': 'PrestaShop', 'version': '', 'raw': ''})

        return cms_list

    def _detect_cdn(self, headers):
        """Detect CDN and proxy services."""
        cdn_list = []

        # Cloudflare
        if headers.get('cf-ray') or headers.get('cf-cache-status') or \
           'cloudflare' in headers.get('server', '').lower():
            cdn_list.append({'category': 'CDN/Security', 'name': 'Cloudflare', 'version': '', 'raw': ''})

        # AWS CloudFront
        if 'cloudfront' in headers.get('via', '').lower() or \
           headers.get('x-amz-cf-id') or headers.get('x-amz-cf-pop'):
            cdn_list.append({'category': 'CDN', 'name': 'AWS CloudFront', 'version': '', 'raw': ''})

        # Akamai
        if headers.get('x-akamai-transformed') or \
           'akamai' in headers.get('server', '').lower() or \
           'akamai' in headers.get('via', '').lower():
            cdn_list.append({'category': 'CDN', 'name': 'Akamai', 'version': '', 'raw': ''})

        # Fastly
        if headers.get('x-fastly-request-id') or 'fastly' in headers.get('via', '').lower():
            cdn_list.append({'category': 'CDN', 'name': 'Fastly', 'version': '', 'raw': ''})

        # Varnish
        if headers.get('x-varnish') or 'varnish' in headers.get('via', '').lower():
            cdn_list.append({'category': 'Cache', 'name': 'Varnish', 'version': '', 'raw': ''})

        # Nginx
        if 'nginx' in headers.get('server', '').lower():
            version = ''
            v = re.search(r'nginx/([\d.]+)', headers.get('server', ''), re.IGNORECASE)
            if v:
                version = v.group(1)
            cdn_list.append({'category': 'Web Server', 'name': 'Nginx', 'version': version, 'raw': ''})

        # Apache
        if 'apache' in headers.get('server', '').lower():
            version = ''
            v = re.search(r'Apache/([\d.]+)', headers.get('server', ''), re.IGNORECASE)
            if v:
                version = v.group(1)
            cdn_list.append({'category': 'Web Server', 'name': 'Apache', 'version': version, 'raw': ''})

        # IIS
        if 'microsoft-iis' in headers.get('server', '').lower():
            version = ''
            v = re.search(r'IIS/([\d.]+)', headers.get('server', ''), re.IGNORECASE)
            if v:
                version = v.group(1)
            cdn_list.append({'category': 'Web Server', 'name': 'Microsoft IIS', 'version': version, 'raw': ''})

        # Incapsula / Imperva
        if headers.get('X-CDN') == 'Imperva' or headers.get('X-Iinfo'):
            cdn_list.append({'category': 'CDN/WAF', 'name': 'Imperva/Incapsula', 'version': '', 'raw': ''})

        # Sucuri
        if 'sucuri' in headers.get('server', '').lower() or headers.get('x-sucuri-id'):
            cdn_list.append({'category': 'WAF', 'name': 'Sucuri', 'version': '', 'raw': ''})

        return cdn_list

    def _detect_js_frameworks(self, body, soup):
        """Detect JavaScript frameworks and libraries."""
        js_list = []

        patterns = {
            'React': (r'react(?:\.min)?\.js|react-dom|__REACT|data-reactroot|_reactRootContainer', None),
            'Angular': (r'ng-version|angular(?:\.min)?\.js|ng-app|ng-controller', r'ng-version="([\d.]+)"'),
            'Vue.js': (r'vue(?:\.min)?\.js|__vue__|data-v-[a-f0-9]', r'vue(?:\.min)?\.js.*?([\d.]+)'),
            'jQuery': (r'jquery(?:\.min)?\.js|jQuery', r'jquery(?:\.min)?\.js.*?([\d.]+)'),
            'Bootstrap': (r'bootstrap(?:\.min)?\.(?:js|css)', r'bootstrap(?:\.min)?\.(?:js|css).*?([\d.]+)'),
            'Next.js': (r'_next/static|__NEXT_DATA__|next\.config', None),
            'Nuxt.js': (r'_nuxt/|__NUXT__|nuxt\.config', None),
            'Svelte': (r'svelte|__svelte', None),
            'Ember.js': (r'ember(?:\.min)?\.js|ember-cli|data-ember', None),
            'Backbone.js': (r'backbone(?:\.min)?\.js', None),
            'Lodash': (r'lodash(?:\.min)?\.js', None),
            'Moment.js': (r'moment(?:\.min)?\.js', None),
            'Axios': (r'axios(?:\.min)?\.js', None),
            'D3.js': (r'd3(?:\.min)?\.js', None),
            'Three.js': (r'three(?:\.min)?\.js', None),
            'Gatsby': (r'gatsby-', None),
            'Tailwind CSS': (r'tailwindcss|tailwind\.', None),
        }

        for name, (detect_pattern, version_pattern) in patterns.items():
            if re.search(detect_pattern, body, re.IGNORECASE):
                version = ''
                if version_pattern:
                    v = re.search(version_pattern, body, re.IGNORECASE)
                    if v:
                        version = v.group(1)
                js_list.append({'category': 'JavaScript', 'name': name, 'version': version, 'raw': ''})

        # Check script tags
        for script in soup.find_all('script', src=True):
            src = script['src']
            # Check for version in script URL
            for name, (detect_pattern, _) in patterns.items():
                if re.search(detect_pattern, src, re.IGNORECASE):
                    version = ''
                    v = re.search(r'[\d]+\.[\d]+\.[\d]+', src)
                    if v:
                        version = v.group()
                    # Don't duplicate
                    if not any(t['name'] == name for t in js_list):
                        js_list.append({'category': 'JavaScript', 'name': name, 'version': version, 'raw': src})

        return js_list

    def _detect_css_frameworks(self, body, soup):
        """Detect CSS frameworks."""
        css_list = []

        css_patterns = {
            'Bootstrap': r'bootstrap(?:\.min)?\.css',
            'Tailwind CSS': r'tailwind',
            'Bulma': r'bulma(?:\.min)?\.css',
            'Foundation': r'foundation(?:\.min)?\.css',
            'Materialize': r'materialize(?:\.min)?\.css',
            'Semantic UI': r'semantic(?:\.min)?\.css',
        }

        for name, pattern in css_patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                if not any(t['name'] == name for t in css_list):
                    version = ''
                    v = re.search(pattern + r'.*?([\d]+\.[\d]+\.[\d]+)', body, re.IGNORECASE)
                    if v:
                        version = v.group(1)
                    css_list.append({'category': 'CSS Framework', 'name': name, 'version': version, 'raw': ''})

        return css_list

    def _detect_analytics(self, body):
        """Detect analytics and tracking scripts."""
        analytics_list = []

        analytics_patterns = {
            'Google Analytics': r'google-analytics\.com|gtag/js|ga\.js|analytics\.js|GoogleAnalyticsObject',
            'Google Tag Manager': r'googletagmanager\.com|gtm\.js',
            'Facebook Pixel': r'fbq\(|facebook\.net/.*fbevents',
            'Hotjar': r'hotjar\.com|hj\(',
            'Mixpanel': r'mixpanel\.com|mixpanel\.init',
            'Segment': r'segment\.com|analytics\.load',
            'Heap': r'heap-\d+\.js|heapanalytics',
            'Matomo/Piwik': r'matomo|piwik',
            'Amplitude': r'amplitude\.com',
            'Intercom': r'intercom\.com|intercomSettings',
            'Drift': r'drift\.com|driftt\.com',
            'Zendesk': r'zendesk\.com|zopim',
            'Crisp': r'crisp\.chat',
            'Tawk.to': r'tawk\.to',
            'Microsoft Clarity': r'clarity\.ms',
            'Cloudflare Web Analytics': r'cloudflareinsights\.com',
        }

        for name, pattern in analytics_patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                analytics_list.append({
                    'category': 'Analytics/Tracking',
                    'name': name,
                    'version': '',
                    'raw': ''
                })

        return analytics_list

    def _detect_languages(self, headers, body):
        """Detect backend programming languages."""
        lang_list = []

        # ASP.NET
        if headers.get('X-AspNet-Version') or headers.get('X-AspNetMvc-Version') or \
           '.aspx' in body.lower() or '.ashx' in body.lower():
            version = headers.get('X-AspNet-Version', headers.get('X-AspNetMvc-Version', ''))
            lang_list.append({'category': 'Backend', 'name': 'ASP.NET', 'version': version, 'raw': ''})

        # PHP
        if 'php' in headers.get('X-Powered-By', '').lower() or '.php' in body.lower():
            version = ''
            v = re.search(r'PHP/([\d.]+)', headers.get('X-Powered-By', ''))
            if v:
                version = v.group(1)
            lang_list.append({'category': 'Backend', 'name': 'PHP', 'version': version, 'raw': ''})

        # Java
        if 'java' in headers.get('X-Powered-By', '').lower() or '.jsp' in body.lower() or \
           '.jsf' in body.lower() or 'jsessionid' in body.lower():
            lang_list.append({'category': 'Backend', 'name': 'Java', 'version': '', 'raw': ''})

        # Python
        if 'python' in headers.get('X-Powered-By', '').lower() or \
           'django' in body.lower() or 'flask' in body.lower():
            lang_list.append({'category': 'Backend', 'name': 'Python', 'version': '', 'raw': ''})

        # Ruby
        if 'phusion passenger' in headers.get('X-Powered-By', '').lower() or \
           'ruby' in headers.get('X-Powered-By', '').lower():
            lang_list.append({'category': 'Backend', 'name': 'Ruby', 'version': '', 'raw': ''})

        # Node.js / Express
        if 'express' in headers.get('X-Powered-By', '').lower():
            lang_list.append({'category': 'Backend', 'name': 'Node.js/Express', 'version': '', 'raw': ''})

        return lang_list

    def _detect_site_type(self, headers, body, soup):
        """Determine if site is static or dynamic."""
        dynamic_indicators = 0
        static_indicators = 0

        # Dynamic indicators
        if any(headers.get(h) for h in ['Set-Cookie', 'X-Powered-By']):
            dynamic_indicators += 2
        if re.search(r'\.(php|asp|aspx|jsp|do|action)', body, re.IGNORECASE):
            dynamic_indicators += 2
        if soup.find('form'):
            dynamic_indicators += 1
        if re.search(r'(api/|/ajax/|XMLHttpRequest|fetch\()', body, re.IGNORECASE):
            dynamic_indicators += 2

        # Static indicators
        if re.search(r'(jekyll|hugo|gatsby|eleventy|hexo)', body, re.IGNORECASE):
            static_indicators += 3
        if headers.get('content-type', '').startswith('text/html') and not headers.get('Set-Cookie'):
            static_indicators += 1
        if not soup.find('form') and not re.search(r'\.php|\.asp|\.jsp', body):
            static_indicators += 1

        if dynamic_indicators > static_indicators:
            return 'Dynamic'
        elif static_indicators > dynamic_indicators:
            return 'Static'
        else:
            return 'Unknown'

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
