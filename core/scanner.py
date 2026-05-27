"""
Main Scanner Orchestrator - Runs all modules and collects results.
"""

import time
from colorama import Fore, Style

from core.http_client import SafeHTTPClient
from core.modules.header_security import HeaderSecurityModule
from core.modules.ssl_tls import SSLTLSModule
from core.modules.csp_analyzer import CSPAnalyzerModule
from core.modules.cookie_analyzer import CookieAnalyzerModule
from core.modules.tech_detector import TechDetectorModule
from core.modules.gdpr_check import GDPRCheckModule
from core.modules.pci_dss_check import PCIDSSCheckModule
from core.modules.info_leakage import InfoLeakageModule
from core.modules.owasp_checks import OWASPCheckModule
from core.modules.external_content import ExternalContentModule
from core.modules.dnssec_check import DNSSECCheckModule
from core.modules.scraping_protection import ScrapingProtectionModule
from core.modules.robots_sitemap import RobotsSitemapModule
from core.modules.js_analyzer import JSAnalyzerModule


class PassiveScanner:
    """Orchestrates all passive scanning modules."""

    MODULE_MAP = {
        'headers': ('HTTP Header Security', HeaderSecurityModule),
        'ssl': ('SSL/TLS Analysis', SSLTLSModule),
        'csp': ('Content Security Policy', CSPAnalyzerModule),
        'cookies': ('Cookie Security', CookieAnalyzerModule),
        'tech': ('Technology Detection', TechDetectorModule),
        'gdpr': ('GDPR Compliance', GDPRCheckModule),
        'pci': ('PCI DSS Compliance', PCIDSSCheckModule),
        'leakage': ('Information Leakage', InfoLeakageModule),
        'owasp': ('OWASP Top 10 Checks', OWASPCheckModule),
        'external': ('External Content', ExternalContentModule),
        'dnssec': ('DNSSEC Configuration', DNSSECCheckModule),
        'scraping': ('Scraping Protection', ScrapingProtectionModule),
        'robots': ('Robots & Sitemap', RobotsSitemapModule),
        'js': ('JavaScript Analysis', JSAnalyzerModule),
    }

    def __init__(self, timeout=15, delay=1.0, user_agent=None,
                 verbose=False, modules=None):
        self.client = SafeHTTPClient(
            timeout=timeout,
            delay=delay,
            user_agent=user_agent,
            verbose=verbose
        )
        self.verbose = verbose
        self.modules_to_run = modules or ['all']

    def scan(self, parsed_url):
        """Run all selected modules against the target."""
        results = {}

        # Initial page fetch
        print(f"{Fore.YELLOW}[*] Fetching main page...")
        main_response = self.client.get(parsed_url['full_url'])

        if not main_response:
            print(f"{Fore.RED}[!] Could not connect to {parsed_url['full_url']}")
            # Try base URL
            main_response = self.client.get(parsed_url['base_url'])
            if not main_response:
                print(f"{Fore.RED}[!] Could not connect to {parsed_url['base_url']}")
                results['error'] = 'Could not connect to target'
                return results

        print(f"{Fore.GREEN}[✓] Connected - Status: {main_response.status_code}")

        # Determine which modules to run
        if 'all' in self.modules_to_run:
            modules_to_run = list(self.MODULE_MAP.keys())
        else:
            modules_to_run = self.modules_to_run

        # Run each module
        for module_key in modules_to_run:
            if module_key not in self.MODULE_MAP:
                continue

            module_name, module_class = self.MODULE_MAP[module_key]
            print(f"{Fore.YELLOW}[*] Running: {module_name}...")

            try:
                module = module_class(self.client, parsed_url, main_response, self.verbose)
                result = module.run()
                results[module_key] = result
                
                # Show quick status
                if result.get('grade'):
                    grade = result['grade']
                    color = Fore.GREEN if grade in ['A+', 'A', 'A-'] else \
                            Fore.YELLOW if grade in ['B+', 'B', 'B-'] else \
                            Fore.RED
                    print(f"{color}    Grade: {grade}")
                
                findings_count = len(result.get('findings', []))
                if findings_count > 0:
                    print(f"{Fore.CYAN}    Findings: {findings_count}")

            except Exception as e:
                print(f"{Fore.RED}    [!] Error in {module_name}: {str(e)}")
                results[module_key] = {
                    'error': str(e),
                    'grade': 'N/A',
                    'findings': []
                }

        # Calculate overall score
        results['overall'] = self._calculate_overall(results)

        return results

    def _calculate_overall(self, results):
        """Calculate overall security score."""
        grade_scores = {
            'A+': 100, 'A': 95, 'A-': 90,
            'B+': 85, 'B': 80, 'B-': 75,
            'C+': 70, 'C': 65, 'C-': 60,
            'D+': 55, 'D': 50, 'D-': 45,
            'F': 30, 'N/A': 0
        }

        scores = []
        all_findings = []
        critical = 0
        high = 0
        medium = 0
        low = 0
        info = 0

        for key, value in results.items():
            if isinstance(value, dict):
                grade = value.get('grade', 'N/A')
                if grade in grade_scores:
                    scores.append(grade_scores[grade])

                for finding in value.get('findings', []):
                    all_findings.append(finding)
                    severity = finding.get('severity', 'info').lower()
                    if severity == 'critical':
                        critical += 1
                    elif severity == 'high':
                        high += 1
                    elif severity == 'medium':
                        medium += 1
                    elif severity == 'low':
                        low += 1
                    else:
                        info += 1

        avg_score = sum(scores) / len(scores) if scores else 0

        if avg_score >= 95:
            overall_grade = 'A+'
        elif avg_score >= 90:
            overall_grade = 'A'
        elif avg_score >= 85:
            overall_grade = 'A-'
        elif avg_score >= 80:
            overall_grade = 'B+'
        elif avg_score >= 75:
            overall_grade = 'B'
        elif avg_score >= 70:
            overall_grade = 'B-'
        elif avg_score >= 65:
            overall_grade = 'C+'
        elif avg_score >= 60:
            overall_grade = 'C'
        elif avg_score >= 55:
            overall_grade = 'C-'
        elif avg_score >= 50:
            overall_grade = 'D'
        else:
            overall_grade = 'F'

        return {
            'grade': overall_grade,
            'score': round(avg_score, 1),
            'total_findings': len(all_findings),
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'info': info
        }
