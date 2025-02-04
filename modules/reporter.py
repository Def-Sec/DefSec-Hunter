from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json
from datetime import datetime

console = Console()

class Reporter:
    def __init__(self, results):
        self.results = results

    def display_report(self):
        self._print_section_header("Enumeration Results")
        self._display_enumeration_results()

        if self.results.get('admin_panels'):
            self._print_section_header("Discovered Admin Panels")
            self._display_admin_panels()

        if self.results.get('enumeration', {}).get('takeover_vulnerabilities'):
            self._print_section_header("Subdomain Takeover Vulnerabilities")
            self._display_takeover_results()

        self._print_section_header("Reconnaissance Results")
        self._display_recon_results()

        self._print_section_header("Port Scan Results")
        self._display_port_scan_results()

        if self.results.get('service_scan'):
            self._print_section_header("Service Scan Results")
            self._display_service_vulnerabilities()

        if self.results.get('vulnerabilities'):
            self._print_section_header("Vulnerability Assessment")
            self._display_vulnerability_results()

        if self.results.get('web_vulnerabilities'):
            self._print_section_header("Web Vulnerability Scan Results")
            self._display_web_vulnerability_results()

        if self.results.get('aws_scan'):
            self._print_section_header("AWS Resource Findings")
            self._display_aws_findings()

        console.print("\n[bible]Remember: \"The LORD will give strength unto his people\" - Psalm 29:11[/bible]")

    def save_report(self, filename):
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.results['target'],
            'results': self.results
        }

        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=4)
            console.print(f"[success]Report saved to {filename}[/]")
        except Exception as e:
            console.print(f"[error]Error saving report: {str(e)}[/]")

    def _print_section_header(self, title):
        console.print(f"\n[cyan]{title}[/]")
        console.print("=" * len(title))

    def _display_recon_results(self):
        recon = self.results['recon']

        console.print("\n[white]IP Addresses:[/]")
        for ip in recon['ip_addresses']:
            console.print(f"  • {ip}")

        console.print("\n[white]DNS Records:[/]")
        for record_type, records in recon['dns_records'].items():
            if records:
                console.print(f"  {record_type}:")
                for record in records:
                    console.print(f"    • {record}")

        if recon['whois_info']:
            console.print("\n[white]WHOIS Information:[/]")
            for key, value in recon['whois_info'].items():
                console.print(f"  • {key}: {value}")

    def _display_port_scan_results(self):
        table = Table(show_header=True, header_style="cyan")
        table.add_column("Port")
        table.add_column("Service")
        table.add_column("State")

        for port, service in self.results['ports'].items():
            table.add_row(str(port), service, "OPEN")

        console.print(table)

    def _display_vulnerability_results(self):
        table = Table(show_header=True, header_style="cyan")
        table.add_column("CVE ID")
        table.add_column("Severity")
        table.add_column("Service")
        table.add_column("Description")

        for vuln in self.results['vulnerabilities']:
            table.add_row(
                vuln['cve_id'],
                vuln['severity'],
                f"{vuln['service']} ({vuln['port']})",
                vuln['description'][:100] + "..."
            )

        console.print(table)

    def _display_web_vulnerability_results(self):
        web_vulns = self.results['web_vulnerabilities']

        # Display XSS Vulnerabilities
        if web_vulns.get('xss_vulnerabilities'):
            self._display_vulnerability_table(
                "Cross-Site Scripting (XSS) Vulnerabilities",
                web_vulns['xss_vulnerabilities']
            )

        # Display SQL Injection Vulnerabilities
        if web_vulns.get('sqli_vulnerabilities'):
            self._display_vulnerability_table(
                "SQL Injection Vulnerabilities",
                web_vulns['sqli_vulnerabilities']
            )

        # Display RCE Vulnerabilities
        if web_vulns.get('rce_vulnerabilities'):
            self._display_vulnerability_table(
                "Remote Code Execution Vulnerabilities",
                web_vulns['rce_vulnerabilities']
            )

        # Display Directory Traversal Vulnerabilities
        if web_vulns.get('traversal_vulnerabilities'):
            self._display_vulnerability_table(
                "Directory Traversal Vulnerabilities",
                web_vulns['traversal_vulnerabilities']
            )

        # Display File Inclusion Vulnerabilities
        if web_vulns.get('lfi_vulnerabilities'):
            self._display_vulnerability_table(
                "File Inclusion Vulnerabilities",
                web_vulns['lfi_vulnerabilities']
            )

        # Display Statistics
        console.print(f"\n[white]Scan Statistics:[/]")
        console.print(f"  • Crawled URLs: {len(web_vulns['crawled_urls'])}")
        console.print(f"  • Forms detected: {len(web_vulns['detected_forms'])}")

    def _display_vulnerability_table(self, title, vulnerabilities):
        console.print(f"\n[red]{title}:[/]")
        table = Table(show_header=True, header_style="cyan")
        table.add_column("URL")
        table.add_column("Parameter")
        table.add_column("Type")
        table.add_column("Payload")

        for vuln in vulnerabilities:
            table.add_row(
                vuln['url'],
                vuln['parameter'],
                vuln['type'],
                vuln['payload']
            )
        console.print(table)
    
    def _display_enumeration_results(self):
        """Display enumeration results"""
        enum_results = self.results.get('enumeration', {})

        if enum_results.get('subdomains'):
            console.print("\n[white]Discovered Subdomains:[/]")
            for subdomain in sorted(enum_results['subdomains']):
                console.print(f"  • {subdomain}")

        if enum_results.get('directories'):
            console.print("\n[white]Discovered Directories:[/]")
            for directory in sorted(enum_results['directories']):
                console.print(f"  • {directory}")

        if enum_results.get('technologies'):
            console.print("\n[white]Detected Technologies:[/]")
            for tech in sorted(enum_results['technologies']):
                console.print(f"  • {tech}")

        if enum_results.get('potential_endpoints'):
            console.print("\n[white]Potential Endpoints:[/]")
            for endpoint in sorted(enum_results['potential_endpoints']):
                console.print(f"  • {endpoint}")

        if enum_results.get('discovered_parameters'):
            console.print("\n[white]Discovered Parameters:[/]")
            for param in sorted(enum_results['discovered_parameters']):
                console.print(f"  • {param}")

        if enum_results.get('custom_payloads'):
            console.print("\n[white]Generated Custom Payloads:[/]")
            for payload in enum_results['custom_payloads']:
                console.print(f"  • {payload}")
    
    def _display_takeover_results(self):
        """Display subdomain takeover vulnerabilities"""
        table = Table(show_header=True, header_style="red")
        table.add_column("Subdomain")
        table.add_column("Type")
        table.add_column("Service/Record")
        table.add_column("Severity")

        takeover_vulns = self.results.get('enumeration', {}).get('takeover_vulnerabilities', [])
        for vuln in takeover_vulns:
            table.add_row(
                vuln['subdomain'],
                vuln['type'],
                vuln.get('service', vuln.get('vulnerable_record', '')),
                f"[bold red]{vuln['severity']}[/]"
            )

        if takeover_vulns:
            console.print(table)
        else:
            console.print("[green]No subdomain takeover vulnerabilities detected.[/]")

    def _display_admin_panels(self):
        """Display discovered admin panels"""
        table = Table(show_header=True, header_style="cyan")
        table.add_column("URL")
        table.add_column("Status")
        table.add_column("Type")
        table.add_column("Confidence")

        for panel in self.results.get('admin_panels', []):
            table.add_row(
                panel['url'],
                str(panel['status_code']),
                panel['type'],
                f"[bold]{panel['confidence']}[/]"
            )

        console.print(table)

    def _display_poc_results(self):
        """Display generated POCs for vulnerabilities"""
        for poc in self.results.get('poc_generated', []):
            console.print(f"\n[cyan]POC for {poc['vulnerability_type']}:[/]")
            console.print(f"Target URL: {poc['target_url']}")
            console.print("\nCurl Command:")
            console.print(f"[green]{poc['curl_command']}[/]")

            console.print("\nPython Code:")
            console.print(Panel(poc['python_code'], title="Python POC", border_style="blue"))

            console.print("\nVerification Steps:")
            for step in poc['verification_steps']:
                console.print(f"  {step}")

            console.print("\n" + "-" * 80)
    
    def _display_aws_findings(self):
        """Display AWS-related findings and exploitation guides"""
        aws_results = self.results.get('aws_scan', {})

        if aws_results.get('buckets'):
            console.print("\n[white]Discovered S3 Buckets:[/]")
            table = Table(show_header=True, header_style="cyan")
            table.add_column("Bucket Name")
            table.add_column("URL")
            table.add_column("Status")
            table.add_column("Accessible")
            table.add_column("Listable")

            for bucket in aws_results['buckets']:
                table.add_row(
                    bucket['name'],
                    bucket['url'],
                    str(bucket['status_code']),
                    "✓" if bucket['accessible'] else "✗",
                    "✓" if bucket['listable'] else "✗"
                )
            console.print(table)

        if aws_results.get('vulnerabilities'):
            console.print("\n[red]AWS Vulnerabilities:[/]")
            table = Table(show_header=True, header_style="red")
            table.add_column("Bucket")
            table.add_column("Type")
            table.add_column("Severity")
            table.add_column("Description")

            for vuln in aws_results['vulnerabilities']:
                table.add_row(
                    vuln['bucket'],
                    vuln['type'],
                    f"[bold red]{vuln['severity']}[/]",
                    vuln['description']
                )
            console.print(table)

        if aws_results.get('exploitation_guides'):
            console.print("\n[yellow]Exploitation Guides:[/]")
            for guide in aws_results['exploitation_guides']:
                console.print(Panel(
                    f"""
[cyan]Vulnerability:[/] {guide['vulnerability']}
[cyan]Target Bucket:[/] {guide['bucket']}
[cyan]Severity:[/] {guide['severity']}

[white]Description:[/]
{guide['description']}

[green]Exploitation Steps:[/]
""" + "\n".join(guide['exploitation_steps']) + """

[red]Mitigation Steps:[/]
""" + "\n".join(guide['mitigation_steps']),
                    title=f"Exploitation Guide - {guide['vulnerability']}",
                    border_style="yellow"
                ))

    def _display_service_vulnerabilities(self):
        """Display service-related vulnerabilities"""
        if self.results.get('service_scan'):
            service_results = self.results['service_scan']

            # Display SSH Results
            if service_results.get('ssh'):
                console.print("\n[red]SSH Service Details:[/]")
                for ssh in service_results['ssh']:
                    console.print(f"Port: {ssh['port']}")
                    console.print(f"Version: {ssh['version']}")
                    if ssh.get('auth_methods'):
                        console.print("Auth Methods:", ", ".join(ssh['auth_methods']))

            # Display FTP Results
            if service_results.get('ftp'):
                console.print("\n[red]FTP Service Details:[/]")
                for ftp in service_results['ftp']:
                    console.print(f"Port: {ftp['port']}")
                    console.print(f"Anonymous Access: {'Yes' if ftp['anonymous_access'] else 'No'}")
                    console.print(f"Banner: {ftp['banner']}")

            # Display RDP Results
            if service_results.get('rdp'):
                console.print("\n[red]RDP Service Details:[/]")
                for rdp in service_results['rdp']:
                    console.print(f"Port: {rdp['port']}")
                    console.print(f"Accessible: {'Yes' if rdp['accessible'] else 'No'}")

            # Display Exploitation Details
            if service_results.get('exploits'):
                console.print("\n[red]Service Exploitation Details:[/]")
                for exploit in service_results['exploits']:
                    console.print(Panel(
                        f"""
[cyan]Service:[/] {exploit['service']} (Port {exploit['port']})
[cyan]Type:[/] {exploit['type']}
[cyan]Severity:[/] [bold red]{exploit.get('severity', 'MEDIUM')}[/]

[white]Description:[/]
{exploit['description']}

[green]Verification Steps:[/]
""" + "\n".join(exploit.get('verification_steps', [])) + """

[red]Mitigation Steps:[/]
""" + "\n".join(exploit.get('mitigation', [])),
                        title=f"Exploitation Guide - {exploit['service']} {exploit['type']}",
                        border_style="yellow"
                    ))