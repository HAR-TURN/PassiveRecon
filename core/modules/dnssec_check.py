"""
DNSSEC Configuration Check Module
"""

import dns.resolver
import dns.rdatatype
import dns.exception


class DNSSECCheckModule:
    """Checks DNSSEC configuration for the domain."""

    def __init__(self, client, parsed_url, response, verbose=False):
        self.client = client
        self.parsed_url = parsed_url
        self.response = response
        self.verbose = verbose

    def run(self):
        findings = []
        score = 100
        dns_info = {}

        domain = self.parsed_url['registered_domain'] or self.parsed_url['hostname']

        # Basic DNS records
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 10

            # A records
            try:
                answers = resolver.resolve(self.parsed_url['hostname'], 'A')
                dns_info['a_records'] = [str(r) for r in answers]
            except Exception:
                dns_info['a_records'] = []

            # AAAA records
            try:
                answers = resolver.resolve(self.parsed_url['hostname'], 'AAAA')
                dns_info['aaaa_records'] = [str(r) for r in answers]
            except Exception:
                dns_info['aaaa_records'] = []

            # MX records
            try:
                answers = resolver.resolve(domain, 'MX')
                dns_info['mx_records'] = [str(r) for r in answers]
            except Exception:
                dns_info['mx_records'] = []

            # NS records
            try:
                answers = resolver.resolve(domain, 'NS')
                dns_info['ns_records'] = [str(r) for r in answers]
            except Exception:
                dns_info['ns_records'] = []

            # TXT records
            try:
                answers = resolver.resolve(domain, 'TXT')
                dns_info['txt_records'] = [str(r) for r in answers]

                # Check for SPF
                spf_found = any('v=spf1' in str(r) for r in answers)
                dns_info['spf'] = spf_found
                if not spf_found:
                    findings.append({
                        'type': 'no_spf',
                        'severity': 'medium',
                        'description': 'No SPF record found',
                        'recommendation': 'Add SPF TXT record for email authentication'
                    })
                    score -= 5

            except Exception:
                dns_info['txt_records'] = []

            # DMARC
            try:
                answers = resolver.resolve(f'_dmarc.{domain}', 'TXT')
                dmarc_records = [str(r) for r in answers]
                dns_info['dmarc'] = True
                dns_info['dmarc_records'] = dmarc_records
            except Exception:
                dns_info['dmarc'] = False
                findings.append({
                    'type': 'no_dmarc',
                    'severity': 'medium',
                    'description': 'No DMARC record found',
                    'recommendation': 'Add DMARC TXT record for email authentication'
                })
                score -= 5

            # DNSSEC check - look for DNSKEY
            try:
                answers = resolver.resolve(domain, 'DNSKEY')
                dns_info['dnssec'] = True
                dns_info['dnskey_records'] = len(answers)
            except dns.resolver.NoAnswer:
                dns_info['dnssec'] = False
                findings.append({
                    'type': 'no_dnssec',
                    'severity': 'medium',
                    'description': 'DNSSEC does not appear to be configured',
                    'recommendation': 'Enable DNSSEC for domain authentication'
                })
                score -= 10
            except dns.resolver.NXDOMAIN:
                dns_info['dnssec'] = False
                findings.append({
                    'type': 'no_dnssec',
                    'severity': 'medium',
                    'description': 'DNSSEC not configured (NXDOMAIN for DNSKEY)',
                    'recommendation': 'Enable DNSSEC'
                })
                score -= 10
            except Exception:
                dns_info['dnssec'] = 'Unknown'

            # Check DS records
            try:
                answers = resolver.resolve(domain, 'DS')
                dns_info['ds_records'] = [str(r) for r in answers]
                dns_info['dnssec_ds'] = True
            except Exception:
                dns_info['ds_records'] = []
                dns_info['dnssec_ds'] = False

            # CAA records
            try:
                answers = resolver.resolve(domain, 'CAA')
                dns_info['caa_records'] = [str(r) for r in answers]
            except Exception:
                dns_info['caa_records'] = []
                findings.append({
                    'type': 'no_caa',
                    'severity': 'low',
                    'description': 'No CAA records found',
                    'recommendation': 'Add CAA records to restrict certificate issuance'
                })
                score -= 3

        except Exception as e:
            findings.append({
                'type': 'dns_error',
                'severity': 'low',
                'description': f'DNS resolution error: {str(e)}',
                'recommendation': 'Verify DNS configuration'
            })
            score -= 5

        score = max(0, score)
        grade = self._score_to_grade(score)

        return {
            'module': 'DNSSEC Configuration',
            'grade': grade,
            'score': score,
            'dns_info': dns_info,
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
