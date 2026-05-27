"""
URL Parser - Handles all URL formats including ports, paths, fragments.
"""

from urllib.parse import urlparse, urlunparse
import re
import tldextract


class URLParser:
    def __init__(self, url):
        self.original_url = url.strip()

    def parse(self):
        """Parse and normalize any URL format."""
        url = self.original_url

        # Add scheme if missing
        if not re.match(r'^https?://', url, re.IGNORECASE):
            url = 'https://' + url

        try:
            parsed = urlparse(url)
        except Exception:
            return None

        if not parsed.hostname:
            return None

        # Extract domain info
        ext = tldextract.extract(url)

        # Determine port
        port = parsed.port
        if not port:
            port = 443 if parsed.scheme == 'https' else 80

        # Build base URL (scheme + host + port if non-standard)
        if (parsed.scheme == 'https' and port == 443) or \
           (parsed.scheme == 'http' and port == 80):
            base_url = f"{parsed.scheme}://{parsed.hostname}"
        else:
            base_url = f"{parsed.scheme}://{parsed.hostname}:{port}"

        # Full URL
        path = parsed.path if parsed.path else '/'
        full_url = base_url + path
        if parsed.query:
            full_url += '?' + parsed.query
        if parsed.fragment:
            full_url += '#' + parsed.fragment

        return {
            'original_url': self.original_url,
            'full_url': full_url,
            'base_url': base_url,
            'scheme': parsed.scheme,
            'hostname': parsed.hostname,
            'domain': parsed.hostname,
            'port': port,
            'path': path,
            'query': parsed.query or '',
            'fragment': parsed.fragment or '',
            'registered_domain': ext.registered_domain,
            'subdomain': ext.subdomain,
            'suffix': ext.suffix,
            'domain_name': ext.domain,
        }
