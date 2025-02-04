"""AWS Scanner Module for DefSec"""
import requests
from rich.console import Console
from typing import Dict, List
import re

console = Console()

class AWSScanner:
    def __init__(self, target: str):
        self.target = target
        self.results = {
            'buckets': [],
            'vulnerabilities': [],
            'exploitation_guides': []
        }

    def scan_aws_resources(self) -> Dict:
        """Scan for AWS-related vulnerabilities"""
        try:
            console.print("[info]Scanning for AWS resources...[/]")
            
            # Extract potential bucket names from target
            self._find_potential_buckets()
            
            # Check bucket permissions
            self._check_bucket_permissions()
            
            # Generate exploitation guides
            self._generate_exploitation_guides()
            
            return self.results
        except Exception as e:
            console.print(f"[error]Error during AWS scanning: {str(e)}[/]")
            return self.results

    def _find_potential_buckets(self):
        """Find potential S3 bucket names based on target domain"""
        bucket_patterns = [
            self.target,
            f"backup.{self.target}",
            f"backup-{self.target}",
            f"media.{self.target}",
            f"static.{self.target}",
            f"assets.{self.target}",
            f"s3.{self.target}",
            f"bucket.{self.target}",
            f"data.{self.target}",
            f"uploads.{self.target}"
        ]

        for pattern in bucket_patterns:
            bucket_names = [
                pattern.replace('.', '-'),
                pattern.replace('.', '_'),
                pattern,
                f"{pattern}-prod",
                f"{pattern}-dev",
                f"{pattern}-stage",
                f"{pattern}-staging",
                f"{pattern}-backup",
                f"{pattern}-media",
                f"{pattern}-static"
            ]
            
            for bucket_name in bucket_names:
                self._check_bucket(bucket_name)

    def _check_bucket(self, bucket_name: str):
        """Check if a bucket exists and is accessible"""
        endpoints = [
            f"http://{bucket_name}.s3.amazonaws.com",
            f"https://{bucket_name}.s3.amazonaws.com"
        ]

        for endpoint in endpoints:
            try:
                response = requests.get(endpoint, timeout=5)
                if response.status_code != 404:
                    self.results['buckets'].append({
                        'name': bucket_name,
                        'url': endpoint,
                        'status_code': response.status_code,
                        'accessible': response.status_code in [200, 403],
                        'listable': 'ListBucket' in response.text
                    })
                    break
            except:
                continue

    def _check_bucket_permissions(self):
        """Check permissions on discovered buckets"""
        for bucket in self.results['buckets']:
            try:
                # Check bucket listing
                list_url = f"https://{bucket['name']}.s3.amazonaws.com/?list-type=2"
                response = requests.get(list_url, timeout=5)
                
                if response.status_code == 200:
                    self.results['vulnerabilities'].append({
                        'bucket': bucket['name'],
                        'type': 'Directory Listing Enabled',
                        'severity': 'HIGH',
                        'description': 'The bucket allows directory listing, exposing its contents to unauthorized users.',
                        'url': list_url
                    })

                # Check bucket policy
                policy_url = f"https://{bucket['name']}.s3.amazonaws.com/?policy"
                response = requests.get(policy_url, timeout=5)
                
                if response.status_code == 200:
                    self.results['vulnerabilities'].append({
                        'bucket': bucket['name'],
                        'type': 'Public Policy Access',
                        'severity': 'CRITICAL',
                        'description': 'The bucket policy is publicly accessible, potentially exposing sensitive configuration.',
                        'url': policy_url
                    })

            except Exception as e:
                console.print(f"[warning]Error checking bucket {bucket['name']}: {str(e)}[/]")

    def _generate_exploitation_guides(self):
        """Generate guidance for exploiting discovered vulnerabilities"""
        for vuln in self.results['vulnerabilities']:
            guide = {
                'vulnerability': vuln['type'],
                'bucket': vuln['bucket'],
                'severity': vuln['severity'],
                'description': vuln['description'],
                'exploitation_steps': [],
                'mitigation_steps': []
            }

            if vuln['type'] == 'Directory Listing Enabled':
                guide['exploitation_steps'] = [
                    f"1. Access the bucket listing: {vuln['url']}",
                    "2. Download files using AWS CLI:",
                    f"   aws s3 sync s3://{vuln['bucket']} ./download/",
                    "3. Analyze downloaded content for sensitive information"
                ]
                guide['mitigation_steps'] = [
                    "1. Disable public access to the bucket",
                    "2. Configure proper bucket policy",
                    "3. Enable bucket logging",
                    "4. Use AWS CloudWatch for monitoring",
                    "5. Implement least privilege access"
                ]

            elif vuln['type'] == 'Public Policy Access':
                guide['exploitation_steps'] = [
                    f"1. View bucket policy: {vuln['url']}",
                    "2. Analyze policy for misconfiguration",
                    "3. Test permissions using AWS CLI:",
                    f"   aws s3api get-bucket-acl --bucket {vuln['bucket']}"
                ]
                guide['mitigation_steps'] = [
                    "1. Remove public policy access",
                    "2. Implement proper IAM roles",
                    "3. Use AWS Organizations for policy management",
                    "4. Enable MFA Delete",
                    "5. Regular security assessments"
                ]

            self.results['exploitation_guides'].append(guide)
