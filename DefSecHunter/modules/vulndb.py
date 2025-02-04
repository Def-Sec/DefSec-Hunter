"""Vulnerability Database Module"""
import requests
from datetime import datetime
from rich.console import Console
import re
import socket
import ssl
from typing import Dict, List, Any
import json
import ftplib
import paramiko
from concurrent.futures import ThreadPoolExecutor

console = Console()

class VulnerabilityDB:
    def __init__(self):
        self.nvd_api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        self.cache = {}
        self.common_vulns = self._load_common_vulns()
        self.target = None
        self.timeout = 5
        self.max_retries = 3

    def _load_common_vulns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load comprehensive vulnerability checks for common services"""
        return {
            'ssh': [
                {
                    'name': 'SSH-CWE-309',
                    'description': 'SSH service allows weak encryption algorithms',
                    'check': self._check_ssh_encryption,
                    'severity': 'HIGH'
                },
                {
                    'name': 'SSH-CWE-287',
                    'description': 'SSH allows keyboard-interactive auth (potential brute-force)',
                    'check': self._check_ssh_auth_methods,
                    'severity': 'MEDIUM'
                },
                {
                    'name': 'SSH-CWE-295',
                    'description': 'SSH supports outdated protocol versions',
                    'check': self._check_ssh_protocol,
                    'severity': 'HIGH'
                }
            ],
            'http': [
                {
                    'name': 'HTTP-CWE-200',
                    'description': 'Web server exposes version information',
                    'check': self._check_http_headers,
                    'severity': 'LOW'
                },
                {
                    'name': 'TLS-CWE-326',
                    'description': 'SSL/TLS service supports weak cipher suites',
                    'check': self._check_ssl_ciphers,
                    'severity': 'HIGH'
                },
                {
                    'name': 'HTTP-CWE-523',
                    'description': 'Insecure HTTP methods enabled',
                    'check': self._check_http_methods,
                    'severity': 'MEDIUM'
                },
                {
                    'name': 'HTTP-CWE-693',
                    'description': 'Missing security headers',
                    'check': self._check_security_headers,
                    'severity': 'MEDIUM'
                }
            ],
            'ftp': [
                {
                    'name': 'FTP-CWE-287',
                    'description': 'FTP allows anonymous access',
                    'check': self._check_ftp_anonymous,
                    'severity': 'HIGH'
                },
                {
                    'name': 'FTP-CWE-522',
                    'description': 'FTP service allows weak authentication',
                    'check': self._check_ftp_auth,
                    'severity': 'HIGH'
                }
            ],
            'mysql': [
                {
                    'name': 'MYSQL-CWE-307',
                    'description': 'MySQL exposed to public network',
                    'check': self._check_mysql_exposure,
                    'severity': 'CRITICAL'
                }
            ],
            'smb': [
                {
                    'name': 'SMB-CWE-434',
                    'description': 'SMB service exposed to internet',
                    'check': self._check_smb_exposure,
                    'severity': 'CRITICAL'
                }
            ],
            'rdp': [
                {
                    'name': 'RDP-CWE-307',
                    'description': 'RDP service allows brute force',
                    'check': self._check_rdp_auth,
                    'severity': 'HIGH'
                }
            ]
        }

    def check_vulnerabilities(self, target: str, open_ports: Dict) -> List[Dict]:
        """Check vulnerabilities with enhanced detection"""
        self.target = target
        vulnerabilities = []

        with ThreadPoolExecutor(max_workers=5) as executor:
            future_to_port = {}

            for port, service_info in open_ports.items():
                service = service_info.get('service', 'unknown')
                banner = service_info.get('banner', '')
                version = service_info.get('version', '')

                if service != "unknown":
                    # Check common vulnerabilities
                    if service in self.common_vulns:
                        for vuln_check in self.common_vulns[service]:
                            future = executor.submit(
                                self._run_vulnerability_check,
                                vuln_check, port, service, banner
                            )
                            future_to_port[future] = (port, service)

                    # Check NVD database
                    future = executor.submit(
                        self._check_nvd_vulnerabilities,
                        service, version, port
                    )
                    future_to_port[future] = (port, service)

            for future in future_to_port:
                try:
                    result = future.result(timeout=30)
                    if result:
                        vulnerabilities.extend(result)
                except Exception as e:
                    port, service = future_to_port[future]
                    console.print(f"[warning]Error checking vulnerabilities for {service} on port {port}: {str(e)}[/]")

        return vulnerabilities

    def _run_vulnerability_check(self, vuln_check: Dict, port: int, service: str, banner: str) -> List[Dict]:
        """Run a single vulnerability check with proper error handling"""
        vulnerabilities = []
        try:
            if vuln_check['check'](port, banner):
                vulnerabilities.append({
                    'name': vuln_check['name'],
                    'description': vuln_check['description'],
                    'service': service,
                    'port': port,
                    'severity': vuln_check['severity'],
                    'type': 'active_check'
                })
        except Exception as e:
            console.print(f"[warning]Error in vulnerability check {vuln_check['name']}: {str(e)}[/]")
        return vulnerabilities

    def _check_nvd_vulnerabilities(self, service: str, version: str, port: int) -> List[Dict]:
        """Check NVD database for vulnerabilities"""
        vulnerabilities = []
        try:
            params = {
                'keyword': f"{service} {version}" if version else service,
                'pubStartDate': self._get_last_year_date(),
                'resultsPerPage': 20
            }

            response = requests.get(self.nvd_api_url, params=params)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('result', {}).get('CVE_Items', []):
                    if self._is_relevant_cve(item, service, version):
                        vuln = {
                            'name': item['cve']['CVE_data_meta']['ID'],
                            'description': item['cve']['description']['description_data'][0]['value'],
                            'service': service,
                            'port': port,
                            'severity': self._get_severity(item),
                            'references': self._get_references(item),
                            'type': 'cve'
                        }
                        vulnerabilities.append(vuln)
        except Exception as e:
            console.print(f"[warning]Error checking NVD for {service}: {str(e)}[/]")
        return vulnerabilities

    def _check_http_methods(self, port: int, banner: str) -> bool:
        """Check for dangerous HTTP methods"""
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS']
        try:
            for method in dangerous_methods:
                response = requests.request(
                    method,
                    f"http://{self.target}:{port}",
                    timeout=self.timeout
                )
                if response.status_code != 405:  # Method not allowed
                    return True
        except:
            pass
        return False

    def _check_security_headers(self, port: int, banner: str) -> bool:
        """Check for missing security headers"""
        security_headers = [
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Content-Security-Policy',
            'Strict-Transport-Security'
        ]
        try:
            response = requests.head(f"http://{self.target}:{port}", timeout=self.timeout)
            return not all(header in response.headers for header in security_headers)
        except:
            return False

    def _check_ssh_protocol(self, port: int, banner: str) -> bool:
        """Check for outdated SSH protocol versions"""
        try:
            if 'ssh-1' in banner.lower() or 'ssh1' in banner.lower():
                return True
            weak_kex = ['diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1']
            return any(alg in banner.lower() for alg in weak_kex)
        except:
            return False

    def _check_ftp_auth(self, port: int, banner: str) -> bool:
        """Check for weak FTP authentication"""
        try:
            with ftplib.FTP(timeout=self.timeout) as ftp:
                ftp.connect(self.target, port)
                try:
                    # Try common weak credentials
                    ftp.login('admin', 'admin')
                    return True
                except:
                    pass
        except:
            pass
        return False

    def _check_smb_exposure(self, port: int, banner: str) -> bool:
        """Check if SMB is exposed to internet"""
        try:
            sock = socket.create_connection((self.target, port), timeout=self.timeout)
            return True
        except:
            return False

    def _check_rdp_auth(self, port: int, banner: str) -> bool:
        """Check RDP authentication security"""
        try:
            sock = socket.create_connection((self.target, port), timeout=self.timeout)
            return True  # If we can connect, it's potentially vulnerable to brute force
        except:
            return False

    def _is_relevant_cve(self, cve_item: Dict, service: str, version: str) -> bool:
        """Determine if a CVE is relevant to the detected service and version"""
        try:
            description = cve_item['cve']['description']['description_data'][0]['value'].lower()
            if not any(term in description for term in [service.lower(), 'remote', 'rce', 'overflow']):
                return False

            if version:
                affected_versions = self._extract_versions_from_cve(cve_item)
                if affected_versions and not any(self._version_matches(version, v) for v in affected_versions):
                    return False

            return True
        except Exception:
            return False

    def _extract_versions_from_cve(self, cve_item: Dict) -> List[str]:
        """Extract affected versions from CVE data"""
        versions = []
        try:
            for node in cve_item.get('configurations', {}).get('nodes', []):
                for cpe in node.get('cpe_match', []):
                    if 'versionStartIncluding' in cpe:
                        versions.append(cpe['versionStartIncluding'])
                    if 'versionEndIncluding' in cpe:
                        versions.append(cpe['versionEndIncluding'])
        except Exception:
            pass
        return versions

    def _version_matches(self, version1: str, version2: str) -> bool:
        """Compare version strings"""
        def normalize_version(v: str) -> List[int]:
            return [int(x) for x in re.findall(r'\d+', v)]

        try:
            v1 = normalize_version(version1)
            v2 = normalize_version(version2)
            return v1 == v2
        except Exception:
            return False

    def _get_references(self, item: Dict) -> List[str]:
        """Extract reference URLs from CVE data"""
        try:
            return [ref['url'] for ref in item['cve']['references']['reference_data']]
        except Exception:
            return []

    def _check_ssh_encryption(self, port: int, banner: str) -> bool:
        """Check for weak SSH encryption"""
        weak_algorithms = ['aes128-cbc', 'aes192-cbc', 'aes256-cbc', '3des-cbc']
        try:
            if any(alg in banner.lower() for alg in weak_algorithms):
                return True
        except Exception:
            pass
        return False

    def _check_ssh_auth_methods(self, port: int, banner: str) -> bool:
        """Check SSH authentication methods"""
        return 'keyboard-interactive' in banner.lower()

    def _check_http_headers(self, port: int, banner: str) -> bool:
        """Check for information disclosure in HTTP headers"""
        try:
            response = requests.head(f"http://{self.target}:{port}", timeout=5)
            sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version']
            return any(h in response.headers.keys() for h in sensitive_headers)
        except Exception:
            pass
        return False

    def _check_ssl_ciphers(self, port: int, banner: str) -> bool:
        """Check for weak SSL/TLS ciphers"""
        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5']
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=self.target) as s:
                s.connect((self.target, port))
                cipher = s.cipher()
                if cipher and cipher[0]:
                    return any(wc in cipher[0] for wc in weak_ciphers)
        except Exception:
            pass
        return False

    def _check_ftp_anonymous(self, port: int, banner: str) -> bool:
        """Check for anonymous FTP access"""
        return 'anonymous' in banner.lower()

    def _check_mysql_exposure(self, port: int, banner: str) -> bool:
        """Check if MySQL is exposed"""
        try:
            sock = socket.create_connection((self.target, port), timeout=5)
            return True
        except Exception:
            pass
        return False

    def _get_last_year_date(self):
        current_year = datetime.now().year - 1
        return f"{current_year}"

    def _get_severity(self, item):
        try:
            impact = item.get('impact', {})
            if 'baseMetricV3' in impact:
                return impact['baseMetricV3']['cvssV3']['baseSeverity']
            elif 'baseMetricV2' in impact:
                return impact['baseMetricV2']['severity']
        except:
            pass
        return "UNKNOWN"