"""
SSL/TLS Certificate Analysis Module
"""

import ssl
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class SSLTLSModule:
    """Analyzes SSL/TLS configuration and certificate."""

    def __init__(self, client, parsed_url, response, verbose=False):
        self.client = client
        self.parsed_url = parsed_url
        self.response = response
        self.verbose = verbose

    def run(self):
        """Run SSL/TLS analysis."""
        findings = []
        cert_info = {}
        tls_info = {}
        score = 100

        hostname = self.parsed_url['hostname']
        port = self.parsed_url['port']

        if self.parsed_url['scheme'] != 'https':
            findings.append({
                'type': 'no_ssl',
                'severity': 'critical',
                'description': 'Site does not use HTTPS',
                'recommendation': 'Enable HTTPS with a valid SSL/TLS certificate'
            })
            return {
                'module': 'SSL/TLS Analysis',
                'grade': 'F',
                'score': 0,
                'certificate': {},
                'tls_info': {},
                'findings': findings
            }

        # Get certificate info
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # TLS version
                    tls_version = ssock.version()
                    tls_info['version'] = tls_version
                    tls_info['cipher'] = ssock.cipher()

                    # Get certificate
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_pem = ssock.getpeercert()

                    if cert_der:
                        cert = x509.load_der_x509_certificate(cert_der, default_backend())
                        
                        cert_info = {
                            'subject': str(cert.subject),
                            'issuer': str(cert.issuer),
                            'serial_number': str(cert.serial_number),
                            'not_before': cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat(),
                            'not_after': cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat(),
                            'signature_algorithm': cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_algorithm_oid.dotted_string),
                            'version': str(cert.version),
                        }

                        # Extract SANs
                        try:
                            san_ext = cert.extensions.get_extension_for_class(
                                x509.SubjectAlternativeName
                            )
                            sans = san_ext.value.get_values_for_type(x509.DNSName)
                            cert_info['san'] = sans
                        except x509.ExtensionNotFound:
                            cert_info['san'] = []

                        # Check expiration
                        not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after
                        now = datetime.utcnow()
                        days_until_expiry = (not_after - now).days

                        cert_info['days_until_expiry'] = days_until_expiry

                        if days_until_expiry < 0:
                            findings.append({
                                'type': 'cert_expired',
                                'severity': 'critical',
                                'description': f'SSL certificate expired {abs(days_until_expiry)} days ago',
                                'recommendation': 'Renew the SSL certificate immediately'
                            })
                            score -= 40
                        elif days_until_expiry < 30:
                            findings.append({
                                'type': 'cert_expiring_soon',
                                'severity': 'high',
                                'description': f'SSL certificate expires in {days_until_expiry} days',
                                'recommendation': 'Renew the SSL certificate before it expires'
                            })
                            score -= 15
                        elif days_until_expiry < 90:
                            findings.append({
                                'type': 'cert_expiring',
                                'severity': 'medium',
                                'description': f'SSL certificate expires in {days_until_expiry} days',
                                'recommendation': 'Plan certificate renewal'
                            })
                            score -= 5

                    # Check TLS version
                    if tls_version:
                        if 'TLSv1.3' in tls_version:
                            tls_info['tls_grade'] = 'Excellent'
                        elif 'TLSv1.2' in tls_version:
                            tls_info['tls_grade'] = 'Good'
                        elif 'TLSv1.1' in tls_version:
                            findings.append({
                                'type': 'weak_tls',
                                'severity': 'high',
                                'description': 'TLSv1.1 is deprecated and insecure',
                                'recommendation': 'Upgrade to TLSv1.2 or TLSv1.3'
                            })
                            score -= 20
                            tls_info['tls_grade'] = 'Poor'
                        elif 'TLSv1.0' in tls_version or 'SSLv' in str(tls_version):
                            findings.append({
                                'type': 'weak_tls',
                                'severity': 'critical',
                                'description': f'{tls_version} is insecure',
                                'recommendation': 'Upgrade to TLSv1.2 or TLSv1.3'
                            })
                            score -= 30
                            tls_info['tls_grade'] = 'Critical'

                    # Check cipher
                    if tls_info.get('cipher'):
                        cipher_name = tls_info['cipher'][0] if tls_info['cipher'] else ''
                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
                        for weak in weak_ciphers:
                            if weak in cipher_name.upper():
                                findings.append({
                                    'type': 'weak_cipher',
                                    'severity': 'high',
                                    'description': f'Weak cipher in use: {cipher_name}',
                                    'recommendation': 'Disable weak ciphers and use strong cipher suites'
                                })
                                score -= 15
                                break

        except ssl.SSLError as e:
            findings.append({
                'type': 'ssl_error',
                'severity': 'high',
                'description': f'SSL Error: {str(e)}',
                'recommendation': 'Fix SSL configuration'
            })
            score -= 20
        except socket.timeout:
            findings.append({
                'type': 'ssl_timeout',
                'severity': 'medium',
                'description': 'SSL connection timed out',
                'recommendation': 'Check server SSL configuration'
            })
            score -= 10
        except Exception as e:
            findings.append({
                'type': 'ssl_check_error',
                'severity': 'low',
                'description': f'Could not complete SSL analysis: {str(e)}',
                'recommendation': 'Manual SSL verification recommended'
            })
            score -= 5

        # Check if HTTP redirects to HTTPS
        if self.parsed_url['scheme'] == 'https':
            http_url = self.parsed_url['full_url'].replace('https://', 'http://', 1)
            http_resp = self.client.get_raw_response(http_url)
            if http_resp and http_resp.status_code not in [301, 302, 307, 308]:
                findings.append({
                    'type': 'no_http_redirect',
                    'severity': 'medium',
                    'description': 'HTTP does not redirect to HTTPS',
                    'recommendation': 'Configure HTTP to HTTPS redirect'
                })
                score -= 10

        score = max(0, score)
        grade = self._score_to_grade(score)

        return {
            'module': 'SSL/TLS Analysis',
            'grade': grade,
            'score': score,
            'certificate': cert_info,
            'tls_info': tls_info,
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
