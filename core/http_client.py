"""
Safe HTTP Client with rate limiting, timeouts, and non-destructive behavior.
"""

import requests
import time
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Suppress insecure request warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SafeHTTPClient:
    """Rate-limited, safe HTTP client for passive reconnaissance."""

    DEFAULT_USER_AGENT = (
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    )

    def __init__(self, timeout=15, delay=1.0, user_agent=None, verbose=False):
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self.user_agent = user_agent or self.DEFAULT_USER_AGENT
        self.last_request_time = 0

        # Create session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

    def _rate_limit(self):
        """Enforce rate limiting between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_request_time = time.time()

    def get(self, url, **kwargs):
        """Safe GET request."""
        self._rate_limit()
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,  # Handle self-signed certs
                allow_redirects=True,
                **kwargs
            )
            return response
        except requests.exceptions.ConnectionError as e:
            if self.verbose:
                print(f"  [!] Connection error for {url}: {e}")
            return None
        except requests.exceptions.Timeout:
            if self.verbose:
                print(f"  [!] Timeout for {url}")
            return None
        except requests.exceptions.RequestException as e:
            if self.verbose:
                print(f"  [!] Request error for {url}: {e}")
            return None

    def head(self, url, **kwargs):
        """Safe HEAD request."""
        self._rate_limit()
        try:
            response = self.session.head(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException:
            return None

    def options(self, url, **kwargs):
        """Safe OPTIONS request."""
        self._rate_limit()
        try:
            response = self.session.options(
                url,
                timeout=self.timeout,
                verify=False,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException:
            return None

    def get_raw_response(self, url):
        """Get response without following redirects."""
        self._rate_limit()
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
            return response
        except requests.exceptions.RequestException:
            return None
