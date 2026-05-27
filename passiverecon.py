#!/usr/bin/env python3
"""
PassiveRecon - Comprehensive Passive Security Scanner
Non-intrusive security analysis tool for any URL/domain.
No API keys required. Safe, rate-limited, and non-destructive.
"""

import argparse
import sys
import os
import json
import time
from datetime import datetime
from colorama import init, Fore, Style, Back

# Initialize colorama
init(autoreset=True)

from core.scanner import PassiveScanner
from core.url_parser import URLParser
from core.report_generator import ReportGenerator

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   {Fore.GREEN}██████╗  █████╗ ███████╗███████╗██╗██╗   ██╗███████╗{Fore.CYAN}          ║
║   {Fore.GREEN}██╔══██╗██╔══██╗██╔════╝██╔════╝██║██║   ██║██╔════╝{Fore.CYAN}          ║
║   {Fore.GREEN}██████╔╝███████║███████╗███████╗██║██║   ██║█████╗  {Fore.CYAN}          ║
║   {Fore.GREEN}██╔═══╝ ██╔══██║╚════██║╚════██║██║╚██╗ ██╔╝██╔══╝  {Fore.CYAN}          ║
║   {Fore.GREEN}██║     ██║  ██║███████║███████║██║ ╚████╔╝ ███████╗{Fore.CYAN}          ║
║   {Fore.GREEN}╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝{Fore.CYAN}          ║
║                                                                  ║
║   {Fore.YELLOW}██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗{Fore.CYAN}                ║
║   {Fore.YELLOW}██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║{Fore.CYAN}                ║
║   {Fore.YELLOW}██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║{Fore.CYAN}                ║
║   {Fore.YELLOW}██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║{Fore.CYAN}                ║
║   {Fore.YELLOW}██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║{Fore.CYAN}                ║
║   {Fore.YELLOW}╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{Fore.CYAN}                ║
║                                                                  ║
║   {Fore.WHITE}Comprehensive Passive Security Scanner v1.0{Fore.CYAN}                  ║
║   {Fore.WHITE}No API Keys | Non-Intrusive | Rate-Limited{Fore.CYAN}                   ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


def parse_arguments():
    parser = argparse.ArgumentParser(
        description='PassiveRecon - Comprehensive Passive Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 passiverecon.py -u https://example.com
  python3 passiverecon.py -u https://trade.swift.co.in:8443/TRADES/#/login
  python3 passiverecon.py -u https://kyc.swift.net/ -o report
  python3 passiverecon.py -u https://example.com --format html json terminal
  python3 passiverecon.py -f urls.txt
  python3 passiverecon.py -u https://example.com --modules headers ssl tech
        """
    )

    parser.add_argument('-u', '--url', type=str, help='Target URL to scan')
    parser.add_argument('-f', '--file', type=str, help='File containing URLs (one per line)')
    parser.add_argument('-o', '--output', type=str, default='reports',
                        help='Output directory for reports (default: reports)')
    parser.add_argument('--format', nargs='+', default=['terminal', 'html', 'json'],
                        choices=['terminal', 'html', 'json'],
                        help='Report formats (default: terminal html json)')
    parser.add_argument('--modules', nargs='+', default=['all'],
                        choices=['all', 'headers', 'ssl', 'csp', 'cookies', 'tech',
                                 'gdpr', 'pci', 'leakage', 'owasp', 'external',
                                 'dnssec', 'scraping', 'robots', 'js'],
                        help='Modules to run (default: all)')
    parser.add_argument('--timeout', type=int, default=15,
                        help='Request timeout in seconds (default: 15)')
    parser.add_argument('--delay', type=float, default=1.0,
                        help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('--user-agent', type=str, default=None,
                        help='Custom User-Agent string')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Suppress banner and progress output')

    return parser.parse_args()


def get_urls(args):
    """Extract URLs from arguments."""
    urls = []

    if args.url:
        urls.append(args.url)

    if args.file:
        if not os.path.exists(args.file):
            print(f"{Fore.RED}[ERROR] File not found: {args.file}")
            sys.exit(1)
        with open(args.file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(line)

    if not urls:
        print(f"{Fore.RED}[ERROR] No target URL specified. Use -u or -f.")
        sys.exit(1)

    return urls


def main():
    args = parse_arguments()

    if not args.quiet:
        print(BANNER)

    urls = get_urls(args)

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    # Initialize scanner
    scanner = PassiveScanner(
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.user_agent,
        verbose=args.verbose,
        modules=args.modules
    )

    # Initialize report generator
    report_gen = ReportGenerator(output_dir=args.output)

    all_results = []

    for i, url in enumerate(urls):
        if not args.quiet:
            print(f"\n{Fore.CYAN}{'='*70}")
            print(f"{Fore.CYAN}[{i+1}/{len(urls)}] Scanning: {Fore.WHITE}{url}")
            print(f"{Fore.CYAN}{'='*70}")

        # Parse and normalize URL
        parser = URLParser(url)
        parsed = parser.parse()

        if not parsed:
            print(f"{Fore.RED}[ERROR] Invalid URL: {url}")
            continue

        if not args.quiet:
            print(f"{Fore.YELLOW}[*] Normalized URL: {parsed['full_url']}")
            print(f"{Fore.YELLOW}[*] Domain: {parsed['domain']}")
            print(f"{Fore.YELLOW}[*] Port: {parsed['port']}")
            print(f"{Fore.YELLOW}[*] Scheme: {parsed['scheme']}")
            print(f"{Fore.YELLOW}[*] Path: {parsed['path']}")

        # Run scan
        start_time = time.time()
        results = scanner.scan(parsed)
        elapsed = time.time() - start_time

        results['scan_metadata'] = {
            'target_url': url,
            'normalized_url': parsed['full_url'],
            'domain': parsed['domain'],
            'scan_time': datetime.now().isoformat(),
            'duration_seconds': round(elapsed, 2),
            'modules_run': args.modules
        }

        all_results.append(results)

        if not args.quiet:
            print(f"\n{Fore.GREEN}[✓] Scan completed in {elapsed:.2f} seconds")

        # Generate reports
        safe_domain = parsed['domain'].replace('.', '_').replace(':', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        if 'terminal' in args.format:
            report_gen.terminal_report(results)

        if 'json' in args.format:
            json_file = os.path.join(args.output, f"{safe_domain}_{timestamp}.json")
            report_gen.json_report(results, json_file)
            if not args.quiet:
                print(f"{Fore.GREEN}[✓] JSON report: {json_file}")

        if 'html' in args.format:
            html_file = os.path.join(args.output, f"{safe_domain}_{timestamp}.html")
            report_gen.html_report(results, html_file)
            if not args.quiet:
                print(f"{Fore.GREEN}[✓] HTML report: {html_file}")

    if not args.quiet:
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.GREEN}[✓] All scans completed. Reports saved to: {args.output}/")
        print(f"{Fore.CYAN}{'='*70}\n")


if __name__ == '__main__':
    main()
