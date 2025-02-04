"""Service Scanner Module for DefSec"""
import socket
import paramiko
import ftplib
from rich.console import Console
from typing import Dict, List
import time
from concurrent.futures import ThreadPoolExecutor

console = Console()

class ServiceScanner:
    def __init__(self, target: str):
        self.target = target
        self.results = {
            'ssh': [],
            'ftp': [],
            'rdp': [],
            'exploits': []
        }
        self.timeout = 5
        self.common_usernames = ['admin', 'root', 'administrator', 'user']
        self.common_passwords = ['admin', 'password', '123456', 'root']

    def scan_services(self, ports: Dict) -> Dict:
        """Scan for vulnerabilities in SSH, FTP, and RDP services"""
        try:
            console.print("[info]Scanning for service vulnerabilities...[/]")

            with ThreadPoolExecutor(max_workers=5) as executor:
                for port, service in ports.items():
                    if port == 22 or 'ssh' in str(service).lower():
                        executor.submit(self._check_ssh, port)
                    elif port == 21 or 'ftp' in str(service).lower():
                        executor.submit(self._check_ftp, port)
                    elif port == 3389 or 'rdp' in str(service).lower():
                        executor.submit(self._check_rdp, port)

            return self.results
        except Exception as e:
            console.print(f"[error]Error during service scanning: {str(e)}[/]")
            return self.results

    def _check_ssh(self, port: int):
        """Check SSH service for vulnerabilities"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                ssh.connect(self.target, port=port, timeout=self.timeout, 
                          username='not_exist_user', password='invalid_pass')
            except paramiko.AuthenticationException:
                # This is good - means SSH is running and requires auth
                transport = ssh.get_transport()
                version = transport.remote_version if transport else "Unknown"

                self.results['ssh'].append({
                    'port': port,
                    'version': version,
                    'auth_methods': self._get_ssh_auth_methods(ssh)
                })

                # Generate detailed exploitation guide
                self.results['exploits'].append({
                    'service': 'SSH',
                    'port': port,
                    'type': 'Brute Force',
                    'severity': 'HIGH',
                    'description': f'SSH service ({version}) is accessible and might be vulnerable to brute force attacks',
                    'verification_steps': [
                        'Hydra SSH brute force:',
                        f'hydra -L users.txt -P pass.txt {self.target} -s {port} ssh -t 4',
                        '\nMetasploit:',
                        f'use auxiliary/scanner/ssh/ssh_login',
                        f'set RHOSTS {self.target}',
                        f'set RPORT {port}',
                        'run'
                    ],
                    'mitigation': [
                        'Implement fail2ban',
                        'Use strong passwords and key-based authentication',
                        'Disable password authentication',
                        'Restrict access by IP',
                        'Use custom SSH port',
                        'Enable two-factor authentication'
                    ]
                })

            except Exception as e:
                if "Connection refused" not in str(e):
                    self.results['exploits'].append({
                        'service': 'SSH',
                        'port': port,
                        'type': 'Configuration',
                        'description': f'SSH service error: {str(e)}',
                        'severity': 'MEDIUM'
                    })
            finally:
                ssh.close()

        except Exception as e:
            console.print(f"[warning]Error checking SSH on port {port}: {str(e)}[/]")

    def _get_ssh_auth_methods(self, ssh) -> List[str]:
        """Get supported SSH authentication methods"""
        try:
            transport = ssh.get_transport()
            if transport:
                return transport.auth_handler.get_allowed_methods('not_exist_user')
        except:
            pass
        return []

    def _check_ftp(self, port: int):
        """Check FTP service for vulnerabilities"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, port, timeout=self.timeout)

            try:
                # Try anonymous login
                ftp.login()
                self.results['ftp'].append({
                    'port': port,
                    'anonymous_access': True,
                    'banner': ftp.getwelcome()
                })

                self.results['exploits'].append({
                    'service': 'FTP',
                    'port': port,
                    'type': 'Anonymous Access',
                    'severity': 'CRITICAL',
                    'description': 'FTP server allows anonymous access - serious security risk',
                    'verification_steps': [
                        f'FTP Connection:',
                        f'ftp {self.target} {port}',
                        'Username: anonymous',
                        'Password: anonymous@domain.com',
                        '\nMetasploit:',
                        'use auxiliary/scanner/ftp/anonymous',
                        f'set RHOSTS {self.target}',
                        f'set RPORT {port}',
                        'run'
                    ],
                    'mitigation': [
                        'Disable anonymous FTP access',
                        'Implement proper authentication',
                        'Use SFTP instead of FTP',
                        'Restrict access by IP',
                        'Enable FTP logging',
                        'Set up chroot jail for FTP users'
                    ]
                })
            except:
                self.results['ftp'].append({
                    'port': port,
                    'anonymous_access': False,
                    'banner': ftp.getwelcome()
                })

                self.results['exploits'].append({
                    'service': 'FTP',
                    'port': port,
                    'type': 'Brute Force',
                    'severity': 'HIGH',
                    'description': 'FTP service might be vulnerable to brute force attacks',
                    'verification_steps': [
                        'Hydra FTP brute force:',
                        f'hydra -L users.txt -P pass.txt ftp://{self.target}:{port}',
                        '\nMetasploit:',
                        'use auxiliary/scanner/ftp/ftp_login',
                        f'set RHOSTS {self.target}',
                        f'set RPORT {port}',
                        'run'
                    ],
                    'mitigation': [
                        'Implement fail2ban',
                        'Use strong passwords',
                        'Consider switching to SFTP',
                        'Restrict access by IP',
                        'Enable FTP logging',
                        'Limit login attempts'
                    ]
                })
            finally:
                ftp.quit()

        except Exception as e:
            console.print(f"[warning]Error checking FTP on port {port}: {str(e)}[/]")

    def _check_rdp(self, port: int):
        """Check RDP service for vulnerabilities"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                self.results['rdp'].append({
                    'port': port,
                    'accessible': True
                })

                self.results['exploits'].append({
                    'service': 'RDP',
                    'port': port,
                    'type': 'Brute Force',
                    'severity': 'HIGH',
                    'description': 'RDP service might be vulnerable to brute force or BlueKeep attacks',
                    'verification_steps': [
                        'Crowbar RDP brute force:',
                        f'crowbar -b rdp -s {self.target}/{port} -u admin -C pass.txt',
                        '\nHydra RDP brute force:',
                        f'hydra -L users.txt -P pass.txt rdp://{self.target}:{port}',
                        '\nMetasploit (BlueKeep):',
                        'use auxiliary/scanner/rdp/cve_2019_0708_bluekeep',
                        f'set RHOSTS {self.target}',
                        f'set RPORT {port}',
                        'run'
                    ],
                    'mitigation': [
                        'Implement account lockout policies',
                        'Use strong passwords',
                        'Enable Network Level Authentication (NLA)',
                        'Restrict access by IP',
                        'Use non-standard port',
                        'Implement 2FA',
                        'Keep system patched for vulnerabilities like BlueKeep'
                    ]
                })

            sock.close()

        except Exception as e:
            console.print(f"[warning]Error checking RDP on port {port}: {str(e)}[/]")