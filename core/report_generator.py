"""
Report Generator - Terminal, JSON, and HTML reports
"""

import json
import os
from datetime import datetime
from colorama import Fore, Style, Back


class ReportGenerator:
    """Generates formatted reports in multiple formats."""

    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir

    def terminal_report(self, results):
        """Print detailed terminal report."""
        meta = results.get('scan_metadata', {})
        overall = results.get('overall', {})

        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.CYAN}  PASSIVE RECON SCAN REPORT")
        print(f"{Fore.CYAN}{'='*70}")
        print(f"{Fore.WHITE}  Target:    {meta.get('target_url', 'N/A')}")
        print(f"{Fore.WHITE}  Domain:    {meta.get('domain', 'N/A')}")
        print(f"{Fore.WHITE}  Scan Time: {meta.get('scan_time', 'N/A')}")
        print(f"{Fore.WHITE}  Duration:  {meta.get('duration_seconds', 'N/A')}s")
        print(f"{Fore.CYAN}{'='*70}")

        # Overall score
        grade = overall.get('grade', 'N/A')
        score = overall.get('score', 0)
        grade_color = Fore.GREEN if grade.startswith('A') else \
                      Fore.YELLOW if grade.startswith('B') else \
                      Fore.RED

        print(f"\n{Fore.WHITE}  ╔══════════════════════════════════════════╗")
        print(f"  ║  OVERALL SECURITY GRADE: {grade_color}{grade:>4}{Fore.WHITE}  ({score}/100)    ║")
        print(f"  ╚══════════════════════════════════════════╝")

        # Finding summary
        print(f"\n{Fore.WHITE}  Finding Summary:")
        print(f"  {Fore.RED}  Critical: {overall.get('critical', 0)}")
        print(f"  {Fore.RED}  High:     {overall.get('high', 0)}")
        print(f"  {Fore.YELLOW}  Medium:   {overall.get('medium', 0)}")
        print(f"  {Fore.CYAN}  Low:      {overall.get('low', 0)}")
        print(f"  {Fore.WHITE}  Info:     {overall.get('info', 0)}")
        print(f"  {Fore.WHITE}  Total:    {overall.get('total_findings', 0)}")

        # Module results
        module_order = ['headers', 'ssl', 'csp', 'cookies', 'tech', 'gdpr',
                        'pci', 'leakage', 'owasp', 'external', 'dnssec',
                        'scraping', 'robots', 'js']

        for key in module_order:
            if key in results and isinstance(results[key], dict):
                module_data = results[key]
                module_name = module_data.get('module', key)
                module_grade = module_data.get('grade', 'N/A')
                module_score = module_data.get('score', 'N/A')

                grade_color = Fore.GREEN if str(module_grade).startswith('A') else \
                              Fore.YELLOW if str(module_grade).startswith('B') else \
                              Fore.RED

                print(f"\n{Fore.CYAN}  ┌─────────────────────────────────────────────────────────────┐")
                print(f"  │ {Fore.WHITE}{module_name:<45} {grade_color}Grade: {module_grade:<4} {Fore.CYAN}│")
                print(f"  └─────────────────────────────────────────────────────────────┘")

                # Module-specific details
                self._print_module_details(key, module_data)

                # Findings
                findings = module_data.get('findings', [])
                if findings:
                    for finding in findings[:10]:
                        severity = finding.get('severity', 'info')
                        sev_color = {
                            'critical': Fore.RED + Style.BRIGHT,
                            'high': Fore.RED,
                            'medium': Fore.YELLOW,
                            'low': Fore.CYAN,
                            'info': Fore.WHITE
                        }.get(severity, Fore.WHITE)

                        print(f"    {sev_color}[{severity.upper():^8}]{Fore.WHITE} {finding.get('description', '')}")

                    if len(findings) > 10:
                        print(f"    {Fore.YELLOW}... and {len(findings)-10} more findings")

        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.GREEN}  Report generation complete.")
        print(f"{Fore.CYAN}{'='*70}\n")

    def _print_module_details(self, key, data):
        """Print module-specific details."""
        if key == 'tech':
            techs = data.get('technologies', [])
            site_type = data.get('site_type', 'Unknown')
            print(f"    {Fore.YELLOW}Site Type: {site_type}")
            if techs:
                print(f"    {Fore.YELLOW}Technologies Detected ({len(techs)}):")
                for tech in techs:
                    version_str = f" v{tech['version']}" if tech.get('version') else ''
                    print(f"      {Fore.WHITE}• [{tech['category']}] {tech['name']}{version_str}")

        elif key == 'ssl':
            cert = data.get('certificate', {})
            tls = data.get('tls_info', {})
            if tls.get('version'):
                print(f"    {Fore.YELLOW}TLS Version: {tls['version']}")
            if cert.get('days_until_expiry'):
                days = cert['days_until_expiry']
                color = Fore.GREEN if days > 90 else Fore.YELLOW if days > 30 else Fore.RED
                print(f"    {Fore.YELLOW}Certificate Expiry: {color}{days} days")
            if cert.get('issuer'):
                print(f"    {Fore.YELLOW}Issuer: {cert['issuer'][:80]}")

        elif key == 'headers':
            present = len(data.get('headers_present', {}))
            missing = len(data.get('headers_missing', {}))
            print(f"    {Fore.GREEN}Headers Present: {present}  {Fore.RED}Missing: {missing}")

        elif key == 'cookies':
            print(f"    {Fore.YELLOW}Cookies Found: {data.get('cookies_found', 0)}")

        elif key == 'leakage':
            print(f"    {Fore.YELLOW}Leaked Keys: {data.get('leaked_keys_count', 0)}")
            print(f"    {Fore.YELLOW}Admin Panels: {data.get('admin_panels_found', 0)}")
            print(f"    {Fore.YELLOW}Sensitive Files: {data.get('sensitive_files_found', 0)}")

        elif key == 'external':
            print(f"    {Fore.YELLOW}External Resources: {data.get('total_external_resources', 0)}")
            print(f"    {Fore.YELLOW}External Domains: {data.get('external_domains_count', 0)}")

        elif key == 'dnssec':
            dns_info = data.get('dns_info', {})
            dnssec = dns_info.get('dnssec', 'Unknown')
            color = Fore.GREEN if dnssec else Fore.RED
            print(f"    {Fore.YELLOW}DNSSEC: {color}{dnssec}")
            print(f"    {Fore.YELLOW}SPF: {dns_info.get('spf', 'N/A')}")
            print(f"    {Fore.YELLOW}DMARC: {dns_info.get('dmarc', 'N/A')}")

        elif key == 'pci':
            print(f"    {Fore.YELLOW}Checks Passed: {data.get('passed', 0)}/{data.get('total', 0)}")

        elif key == 'js':
            print(f"    {Fore.YELLOW}JS Files Found: {data.get('js_files_found', 0)}")
            print(f"    {Fore.YELLOW}JS Files Analyzed: {data.get('js_files_analyzed', 0)}")
            print(f"    {Fore.YELLOW}Secrets Found: {data.get('secrets_found', 0)}")

    def json_report(self, results, filepath):
        """Generate JSON report."""

        def clean_for_json(obj):
            if isinstance(obj, dict):
                return {k: clean_for_json(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [clean_for_json(i) for i in obj]
            elif isinstance(obj, (int, float, str, bool, type(None))):
                return obj
            else:
                return str(obj)

        clean_results = clean_for_json(results)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(clean_results, f, indent=2, ensure_ascii=False, default=str)

    def html_report(self, results, filepath):
        """Generate HTML report."""
        meta = results.get('scan_metadata', {})
        overall = results.get('overall', {})

        grade = overall.get('grade', 'N/A')
        grade_class = 'grade-a' if grade.startswith('A') else \
                      'grade-b' if grade.startswith('B') else \
                      'grade-c' if grade.startswith('C') else 'grade-f'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PassiveRecon Report - {meta.get('domain', '')}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
               background: #0a0e17; color: #e0e0e0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1a1f36, #0d1117);
                   border: 1px solid #30363d; border-radius: 12px;
                   padding: 30px; margin-bottom: 20px; text-align: center; }}
        .header h1 {{ color: #58a6ff; font-size: 2em; margin-bottom: 10px; }}
        .header .target {{ color: #8b949e; font-size: 1.1em; }}
        .overall-grade {{ display: inline-block; padding: 20px 40px;
                          border-radius: 12px; font-size: 3em; font-weight: bold;
                          margin: 20px 0; }}
        .grade-a {{ background: #0d4429; color: #3fb950; border: 2px solid #3fb950; }}
        .grade-b {{ background: #3d2e00; color: #d29922; border: 2px solid #d29922; }}
        .grade-c {{ background: #42200e; color: #db6d28; border: 2px solid #db6d28; }}
        .grade-f {{ background: #3d0000; color: #f85149; border: 2px solid #f85149; }}
        .stats {{ display: flex; justify-content: center; gap: 20px;
                  flex-wrap: wrap; margin: 20px 0; }}
        .stat {{ background: #161b22; padding: 15px 25px; border-radius: 8px;
                 border: 1px solid #30363d; text-align: center; }}
        .stat-number {{ font-size: 1.8em; font-weight: bold; }}
        .stat-label {{ font-size: 0.85em; color: #8b949e; }}
        .critical {{ color: #f85149; }}
        .high {{ color: #f85149; }}
        .medium {{ color: #d29922; }}
        .low {{ color: #58a6ff; }}
        .info {{ color: #8b949e; }}
        .module {{ background: #161b22; border: 1px solid #30363d;
                   border-radius: 12px; margin-bottom: 15px; overflow: hidden; }}
        .module-header {{ background: #1a1f36; padding: 15px 20px;
                          display: flex; justify-content: space-between;
                          align-items: center; cursor: pointer;
                          border-bottom: 1px solid #30363d; }}
        .module-header h2 {{ font-size: 1.1em; color: #c9d1d9; }}
        .module-grade {{ padding: 5px 15px; border-radius: 6px;
                         font-weight: bold; font-size: 0.95em; }}
        .module-body {{ padding: 20px; }}
        .finding {{ padding: 12px 15px; margin: 8px 0; border-radius: 8px;
                    border-left: 4px solid; }}
        .finding.critical {{ background: #1a0000; border-color: #f85149; }}
        .finding.high {{ background: #1a0000; border-color: #f85149; }}
        .finding.medium {{ background: #1a1200; border-color: #d29922; }}
        .finding.low {{ background: #0a1a2a; border-color: #58a6ff; }}
        .finding.info {{ background: #0d1117; border-color: #8b949e; }}
        .finding-severity {{ font-weight: bold; text-transform: uppercase;
                             font-size: 0.75em; margin-bottom: 4px; }}
        .finding-desc {{ font-size: 0.95em; }}
        .finding-rec {{ font-size: 0.85em; color: #8b949e; margin-top: 6px;
                        font-style: italic; }}
        .tech-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
                      gap: 10px; margin: 10px 0; }}
        .tech-card {{ background: #0d1117; border: 1px solid #30363d;
                      border-radius: 8px; padding: 12px; }}
        .tech-category {{ font-size: 0.75em; color: #58a6ff; text-transform: uppercase; }}
        .tech-name {{ font-weight: bold; color: #c9d1d9; }}
        .tech-version {{ color: #3fb950; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th {{ background: #1a1f36; padding: 10px; text-align: left;
             border: 1px solid #30363d; color: #58a6ff; }}
        td {{ padding: 10px; border: 1px solid #30363d; }}
        .footer {{ text-align: center; padding: 20px; color: #8b949e;
                   font-size: 0.85em; margin-top: 20px; }}
        details {{ margin: 5px 0; }}
        summary {{ cursor: pointer; padding: 8px; background: #0d1117;
                   border-radius: 6px; }}
        summary:hover {{ background: #1a1f36; }}
        .pass {{ color: #3fb950; }}
        .fail {{ color: #f85149; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ PassiveRecon Security Report</h1>
            <div class="target">{meta.get('target_url', 'N/A')}</div>
            <div class="target">Scanned: {meta.get('scan_time', 'N/A')} | Duration: {meta.get('duration_seconds', 'N/A')}s</div>
            <div class="overall-grade {grade_class}">{grade}</div>
            <div style="color: #8b949e;">Overall Score: {overall.get('score', 0)}/100</div>

            <div class="stats">
                <div class="stat">
                    <div class="stat-number critical">{overall.get('critical', 0)}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-number high">{overall.get('high', 0)}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat">
                    <div class="stat-number medium">{overall.get('medium', 0)}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-number low">{overall.get('low', 0)}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat">
                    <div class="stat-number info">{overall.get('info', 0)}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>
        </div>
"""

        # Module sections
        module_order = ['headers', 'ssl', 'csp', 'cookies', 'tech', 'gdpr',
                        'pci', 'leakage', 'owasp', 'external', 'dnssec',
                        'scraping', 'robots', 'js']

        for key in module_order:
            if key in results and isinstance(results[key], dict):
                module_data = results[key]
                module_name = module_data.get('module', key)
                module_grade = module_data.get('grade', 'N/A')

                m_grade_class = 'grade-a' if str(module_grade).startswith('A') else \
                                'grade-b' if str(module_grade).startswith('B') else \
                                'grade-c' if str(module_grade).startswith('C') else 'grade-f'

                html += f"""
        <div class="module">
            <div class="module-header" onclick="this.parentElement.querySelector('.module-body').style.display = this.parentElement.querySelector('.module-body').style.display === 'none' ? 'block' : 'none'">
                <h2>{module_name}</h2>
                <span class="module-grade {m_grade_class}">{module_grade}</span>
            </div>
            <div class="module-body">
"""
                # Module-specific content
                html += self._html_module_details(key, module_data)

                # Findings
                findings = module_data.get('findings', [])
                if findings:
                    html += '<h3 style="margin: 15px 0 10px; color: #c9d1d9;">Findings</h3>'
                    for finding in findings:
                        severity = finding.get('severity', 'info')
                        html += f"""
                <div class="finding {severity}">
                    <div class="finding-severity {severity}">{severity}</div>
                    <div class="finding-desc">{self._html_escape(finding.get('description', ''))}</div>
                    <div class="finding-rec">💡 {self._html_escape(finding.get('recommendation', ''))}</div>
                </div>"""
                else:
                    html += '<p style="color: #3fb950; padding: 10px;">✅ No issues found</p>'

                html += """
            </div>
        </div>"""

        html += f"""
        <div class="footer">
            <p>Generated by PassiveRecon v1.0 | Passive Security Scanner</p>
            <p>This scan was performed passively without any intrusive testing.</p>
        </div>
    </div>
    <script>
        // Auto-collapse modules
        document.querySelectorAll('.module-body').forEach(el => el.style.display = 'block');
    </script>
</body>
</html>"""

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)

    def _html_module_details(self, key, data):
        """Generate module-specific HTML details."""
        html = ''

        if key == 'tech':
            techs = data.get('technologies', [])
            site_type = data.get('site_type', 'Unknown')
            html += f'<p><strong>Site Type:</strong> {site_type}</p>'
            if techs:
                html += '<div class="tech-grid">'
                for tech in techs:
                    version = f'<span class="tech-version">v{tech["version"]}</span>' if tech.get('version') else ''
                    html += f"""
                    <div class="tech-card">
                        <div class="tech-category">{self._html_escape(tech['category'])}</div>
                        <div class="tech-name">{self._html_escape(tech['name'])} {version}</div>
                    </div>"""
                html += '</div>'

        elif key == 'headers':
            present = data.get('headers_present', {})
            missing = data.get('headers_missing', {})
            info_disc = data.get('information_disclosure', {})

            html += '<table>'
            html += '<tr><th>Header</th><th>Status</th><th>Value / Info</th></tr>'
            for h, info in present.items():
                html += f'<tr><td>{self._html_escape(h)}</td><td class="pass">✅ Present</td><td>{self._html_escape(str(info.get("value", ""))[:100])}</td></tr>'
            for h, info in missing.items():
                html += f'<tr><td>{self._html_escape(h)}</td><td class="fail">❌ Missing</td><td>{self._html_escape(info.get("recommendation", ""))}</td></tr>'
            html += '</table>'

            if info_disc:
                html += '<h4 style="margin: 10px 0; color: #d29922;">⚠️ Information Disclosure</h4><table>'
                html += '<tr><th>Header</th><th>Value</th></tr>'
                for h, v in info_disc.items():
                    html += f'<tr><td>{self._html_escape(h)}</td><td>{self._html_escape(v)}</td></tr>'
                html += '</table>'

        elif key == 'ssl':
            cert = data.get('certificate', {})
            tls = data.get('tls_info', {})
            if tls:
                html += f'<p><strong>TLS Version:</strong> {tls.get("version", "N/A")}</p>'
            if cert:
                html += '<table>'
                for k, v in cert.items():
                    if k != 'san':
                        html += f'<tr><td><strong>{k}</strong></td><td>{self._html_escape(str(v)[:150])}</td></tr>'
                html += '</table>'
                if cert.get('san'):
                    html += f'<p><strong>SANs:</strong> {", ".join(cert["san"][:10])}</p>'

        elif key == 'cookies':
            cookies = data.get('cookies', [])
            if cookies:
                html += '<table>'
                html += '<tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Expires</th></tr>'
                for c in cookies:
                    sec = '✅' if c.get('secure') else '❌'
                    http = '✅' if c.get('httponly') else '❌'
                    same = c.get('samesite') or '❌ Missing'
                    html += f'<tr><td>{self._html_escape(c["name"])}</td><td>{sec}</td><td>{http}</td><td>{same}</td><td>{c.get("expires", "")}</td></tr>'
                html += '</table>'

        elif key == 'csp':
            directives = data.get('directives', {})
            if directives:
                html += '<table><tr><th>Directive</th><th>Values</th></tr>'
                for d, vals in directives.items():
                    html += f'<tr><td>{self._html_escape(d)}</td><td>{self._html_escape(" ".join(vals))}</td></tr>'
                html += '</table>'

        elif key == 'dnssec':
            dns_info = data.get('dns_info', {})
            if dns_info:
                html += '<table>'
                for k, v in dns_info.items():
                    if isinstance(v, list):
                        v = ', '.join(str(i) for i in v[:5])
                    html += f'<tr><td><strong>{k}</strong></td><td>{self._html_escape(str(v)[:200])}</td></tr>'
                html += '</table>'

        elif key == 'pci':
            checks = data.get('checks', {})
            if checks:
                html += '<table><tr><th>Check</th><th>Status</th></tr>'
                for k, v in checks.items():
                    cls = 'pass' if v == 'PASS' else 'fail'
                    html += f'<tr><td>{self._html_escape(k)}</td><td class="{cls}">{v}</td></tr>'
                html += '</table>'

        elif key == 'external':
            html += f'<p>Total External Resources: {data.get("total_external_resources", 0)}</p>'
            html += f'<p>External Domains: {data.get("external_domains_count", 0)}</p>'
            domains = data.get('external_domains', [])
            if domains:
                html += '<details><summary>External Domains</summary><ul>'
                for d in domains[:30]:
                    html += f'<li>{self._html_escape(d)}</li>'
                html += '</ul></details>'

        elif key == 'gdpr':
            checks = data.get('checks', {})
            if checks:
                html += '<table><tr><th>Check</th><th>Status</th></tr>'
                for k, v in checks.items():
                    if isinstance(v, list):
                        status = ', '.join(v) if v else 'None'
                        html += f'<tr><td>{k}</td><td>{self._html_escape(status)}</td></tr>'
                    elif isinstance(v, bool):
                        cls = 'pass' if v else 'fail'
                        html += f'<tr><td>{k}</td><td class="{cls}">{"✅" if v else "❌"}</td></tr>'
                    else:
                        html += f'<tr><td>{k}</td><td>{self._html_escape(str(v))}</td></tr>'
                html += '</table>'

        elif key == 'js':
            html += f'<p>JS Files Found: {data.get("js_files_found", 0)} | '
            html += f'Analyzed: {data.get("js_files_analyzed", 0)} | '
            html += f'Secrets Found: {data.get("secrets_found", 0)}</p>'

        return html

    def _html_escape(self, text):
        """Escape HTML special characters."""
        if not isinstance(text, str):
            text = str(text)
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;') \
                    .replace('"', '&quot;').replace("'", '&#x27;')
