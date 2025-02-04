"""POC Generator Module for DefSec"""
from rich.console import Console
from typing import Dict, List

console = Console()

class POCGenerator:
    def __init__(self, target: str):
        self.target = target

    def generate_pocs(self, results: Dict) -> List[Dict]:
        """Generate proof of concepts for discovered vulnerabilities"""
        pocs = []
        
        # Generate POCs for service vulnerabilities
        if 'service_scan' in results and results['service_scan'].get('exploits'):
            for exploit in results['service_scan']['exploits']:
                poc = self._generate_service_poc(exploit)
                if poc:
                    pocs.append(poc)

        # Generate POCs for AWS vulnerabilities
        if 'aws_scan' in results and results['aws_scan'].get('vulnerabilities'):
            for vuln in results['aws_scan']['vulnerabilities']:
                poc = self._generate_aws_poc(vuln)
                if poc:
                    pocs.append(poc)

        return pocs

    def _generate_service_poc(self, exploit: Dict) -> Dict:
        """Generate POC for service-related vulnerabilities"""
        poc = {
            'vulnerability_type': exploit['type'],
            'target_url': f"{self.target}:{exploit.get('port', '')}",
            'severity': exploit.get('severity', 'MEDIUM'),
            'description': exploit['description'],
            'curl_command': '',
            'python_code': '',
            'verification_steps': exploit.get('verification_steps', [])
        }

        if exploit['service'] == 'SSH':
            poc['curl_command'] = 'N/A - Use SSH client'
            poc['python_code'] = self._generate_ssh_poc_code()
        elif exploit['service'] == 'FTP':
            poc['curl_command'] = 'N/A - Use FTP client'
            poc['python_code'] = self._generate_ftp_poc_code(exploit)
        elif exploit['service'] == 'RDP':
            poc['curl_command'] = 'N/A - Use RDP client'
            poc['python_code'] = self._generate_rdp_poc_code()

        return poc

    def _generate_aws_poc(self, vuln: Dict) -> Dict:
        """Generate POC for AWS-related vulnerabilities"""
        poc = {
            'vulnerability_type': vuln['type'],
            'target_url': f"s3://{vuln['bucket']}",
            'severity': vuln['severity'],
            'description': vuln['description'],
            'curl_command': f"aws s3 ls s3://{vuln['bucket']}",
            'python_code': self._generate_aws_poc_code(vuln),
            'verification_steps': [
                f"1. Configure AWS CLI with credentials",
                f"2. Run the curl command or Python script",
                f"3. Check for successful access to the bucket",
                f"4. Document findings and potential data exposure"
            ]
        }
        return poc

    def _generate_ssh_poc_code(self) -> str:
        return '''
import paramiko

def test_ssh_connection(host, port=22, username="root", password="password"):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port=port, username=username, password=password)
        print(f"[+] Successful login to {host}:{port}")
        ssh.close()
    except Exception as e:
        print(f"[-] Connection failed: {str(e)}")

# Usage
test_ssh_connection("target_host", port=22)
'''

    def _generate_ftp_poc_code(self, exploit: Dict) -> str:
        if exploit.get('type') == 'Anonymous Access':
            return '''
from ftplib import FTP

def test_anonymous_ftp(host, port=21):
    try:
        ftp = FTP()
        ftp.connect(host, port)
        ftp.login()  # Anonymous login
        print(f"[+] Anonymous FTP access successful on {host}:{port}")
        print("Available files:")
        ftp.dir()
        ftp.quit()
    except Exception as e:
        print(f"[-] Connection failed: {str(e)}")

# Usage
test_anonymous_ftp("target_host", port=21)
'''
        else:
            return '''
from ftplib import FTP

def test_ftp_connection(host, port=21, username="anonymous", password="guest@example.com"):
    try:
        ftp = FTP()
        ftp.connect(host, port)
        ftp.login(username, password)
        print(f"[+] FTP login successful on {host}:{port}")
        print("Available files:")
        ftp.dir()
        ftp.quit()
    except Exception as e:
        print(f"[-] Connection failed: {str(e)}")

# Usage
test_ftp_connection("target_host", port=21)
'''

    def _generate_rdp_poc_code(self) -> str:
        return '''
# RDP Connection Test using xfreerdp
# Note: This requires xfreerdp to be installed

import subprocess

def test_rdp_connection(host, port=3389):
    try:
        command = [
            "xfreerdp", 
            f"/v:{host}:{port}",
            "/cert-ignore",
            "+clipboard",
            "/dynamic-resolution"
        ]
        
        print(f"[+] Attempting RDP connection to {host}:{port}")
        print("[*] Command to run manually:")
        print(" ".join(command))
        
    except Exception as e:
        print(f"[-] Error preparing RDP connection: {str(e)}")

# Usage
test_rdp_connection("target_host", port=3389)
'''

    def _generate_aws_poc_code(self, vuln: Dict) -> str:
        return f'''
import boto3
from botocore.exceptions import ClientError

def test_s3_access(bucket_name="{vuln['bucket']}"):
    try:
        s3 = boto3.client('s3')
        
        # Test bucket listing
        response = s3.list_objects_v2(Bucket=bucket_name)
        print(f"[+] Successfully listed bucket contents")
        
        for obj in response.get('Contents', []):
            print(f"Found object: {obj['Key']}")
            
    except ClientError as e:
        print(f"[-] Error: {str(e)}")

# Usage
test_s3_access()
'''
