#!/usr/bin/env python3
import argparse
import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress
from rich.theme import Theme
from rich.live import Live
from rich.text import Text
from rich.table import Table
import yaml
from modules.recon import Reconnaissance
from modules.scanner import PortScanner
from modules.vulndb import VulnerabilityDB
from modules.webvuln import WebVulnScanner
from modules.reporter import Reporter
from modules.shell import DefSecShell
from utils.validators import validate_target
from modules.enum import Enumerator
from modules.aws_scanner import AWSScanner
from utils.bible_verses import get_random_verse
from modules.service_scanner import ServiceScanner
from modules.poc_generator import POCGenerator

# DefSec custom theme
custom_theme = Theme({
    'info': 'cyan',
    'warning': 'yellow',
    'error': 'red',
    'success': 'green',
    'bible': 'yellow italic',
    'loading': 'cyan'
})

console = Console(theme=custom_theme)

def show_loading_screen():
    """Display an animated loading screen with varied messages"""
    frames = [
        "⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"
    ]

    messages = [
        "Initializing DefSec Security Tool",
        "Loading Scanner Modules",
        "Calibrating Network Probes",
        "Loading Vulnerability Database",
        "Preparing Service Scanners",
        "Configuring AWS Scanner",
        "Loading Enumeration Module",
        "Initializing SSH Scanner",
        "Preparing FTP Scanner",
        "Loading RDP Scanner",
        "Configuring POC Generator",
        "Loading Exploit Templates",
        "Preparing Port Scanner",
        "Loading Security Modules",
        "Initializing Report Generator"
    ]

    console.clear()
    console.print("\n" * 2)

    with Live(console=console, refresh_per_second=15) as live:
        for message in messages:
            for _ in range(3):  # Show each message for ~0.5 seconds
                for frame in frames:
                    text = Text()
                    text.append(frame, style="loading")
                    text.append(" ")
                    text.append(message, style="white")
                    text.append("...")
                    live.update(text)
                    time.sleep(0.02)  # Smooth animation
            time.sleep(0.1)  # Small pause between messages

    console.print("\n" * 2)

def display_scan_results(results: dict):
        """Display scan results in a formatted way"""
        console.print("\n[cyan]Enumeration Results[/cyan]")
        console.print("=" * 20)
        if results.get('enumeration'):
            if 'directories' in results['enumeration']:
                if isinstance(results['enumeration']['directories'], set):
                    directories = sorted(list(results['enumeration']['directories']))
                else:
                    directories = results['enumeration']['directories']
                console.print("\nDiscovered Directories:")
                for directory in directories:
                    console.print(f"  • {directory}")

            if 'technologies' in results['enumeration']:
                console.print("\nDetected Technologies:")
                if isinstance(results['enumeration']['technologies'], dict):
                    for tech, version in results['enumeration']['technologies'].items():
                        console.print(f"  • {tech}: {version}")
                elif isinstance(results['enumeration']['technologies'], set):
                    for tech in sorted(results['enumeration']['technologies']):
                        console.print(f"  • {tech}")

        console.print("\n[cyan]Reconnaissance Results[/cyan]")
        console.print("=" * 20)
        if results.get('recon'):
            if 'ip_addresses' in results['recon']:
                console.print("\nIP Addresses:")
                for ip in results['recon']['ip_addresses']:
                    console.print(f"  • {ip}")

            if 'dns_records' in results['recon']:
                console.print("\nDNS Records:")
                for record_type, records in results['recon']['dns_records'].items():
                    console.print(f"  {record_type}:")
                    for record in records:
                        console.print(f"    • {record}")

            if 'whois' in results['recon']:
                console.print("\nWHOIS Information:")
                for key, value in results['recon']['whois'].items():
                    console.print(f"  • {key}: {value}")

        console.print("\n[cyan]Port Scan Results[/cyan]")
        console.print("=" * 20)
        if results.get('ports'):
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Port")
            table.add_column("Service")
            table.add_column("Version")
            table.add_column("State")

            for port, info in results['ports'].items():
                table.add_row(
                    str(port),
                    info.get('service', 'unknown'),
                    info.get('version', 'unknown'),
                    info.get('state', 'unknown')
                )
            console.print(table)

        console.print("\n[cyan]Vulnerability Results[/cyan]")
        console.print("=" * 20)

        if results.get('web_vulnerabilities', {}).get('xss_vulnerabilities'):
            console.print("\n[red]XSS Vulnerabilities:[/red]")
            for vuln in results['web_vulnerabilities']['xss_vulnerabilities']:
                console.print(f"  • URL: {vuln['url']}")
                console.print(f"    Parameter: {vuln['parameter']}")
                console.print(f"    Type: {vuln['type']}")
                console.print(f"    Payload: {vuln['payload']}")

        if results.get('web_vulnerabilities', {}).get('sqli_vulnerabilities'):
            console.print("\n[red]SQL Injection Vulnerabilities:[/red]")
            for vuln in results['web_vulnerabilities']['sqli_vulnerabilities']:
                console.print(f"  • URL: {vuln['url']}")
                console.print(f"    Parameter: {vuln['parameter']}")
                console.print(f"    Type: {vuln['type']}")
                console.print(f"    Payload: {vuln['payload']}")

        if results.get('web_vulnerabilities', {}).get('rce_vulnerabilities'):
            console.print("\n[red]Remote Code Execution Vulnerabilities:[/red]")
            for vuln in results['web_vulnerabilities']['rce_vulnerabilities']:
                console.print(f"  • URL: {vuln['url']}")
                console.print(f"    Parameter: {vuln['parameter']}")
                console.print(f"    Payload: {vuln['payload']}")

        console.print("\n[cyan]Summary[/cyan]")
        console.print("=" * 20)
        web_vulns = results.get('web_vulnerabilities', {})
        console.print(f"XSS Vulnerabilities: {len(web_vulns.get('xss_vulnerabilities', []))}")
        console.print(f"SQL Injection Vulnerabilities: {len(web_vulns.get('sqli_vulnerabilities', []))}")
        console.print(f"RCE Vulnerabilities: {len(web_vulns.get('rce_vulnerabilities', []))}")

def load_config():
    try:
        with open('config/default.yaml', 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        console.print("[error]Error loading configuration file[/]")
        sys.exit(1)

def print_banner():
    verse, text = get_random_verse()

    console.print(Panel.fit(f"""
[cyan]
██████╗ ███████╗███████╗███████╗███████╗ ██████╗
██╔══██╗██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝
██║  ██║█████╗  █████╗  ███████╗█████╗  ██║     
██║  ██║██╔══╝  ██╔══╝  ╚════██║██╔══╝  ██║     
██████╔╝███████╗██║     ███████║███████╗╚██████╗
╚═════╝ ╚══════╝╚═╝     ╚══════╝╚══════╝ ╚═════╝
[/cyan]
[white]Professional Security Testing Tool[/white]

[bible]Daily Encouragement:
{text}
- {verse}[/bible]
""", title="DefSec v1.0", border_style="cyan"))

def main():
    parser = argparse.ArgumentParser(description="DefSec Security Testing Tool")
    parser.add_argument("-t", "--target", required=True, help="Target domain or IP address")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
    parser.add_argument("-o", "--output", help="Output report file")
    parser.add_argument("--no-vuln-check", action="store_true", help="Skip vulnerability checks")
    parser.add_argument("--no-web-scan", action="store_true", help="Skip web vulnerability scanning")
    parser.add_argument("--no-enum", action="store_true", help="Skip enumeration phase")
    parser.add_argument("--no-aws", action="store_true", help="Skip AWS resource scanning")
    args = parser.parse_args()

    show_loading_screen()
    print_banner()
    config = load_config()

    # Validate target
    if not validate_target(args.target):
        console.print("[error]Invalid target specified[/]")
        sys.exit(1)

    console.print(f"\n[info]Starting security assessment for target: [/][white]{args.target}[/]")
    console.print("[info]DefSec - Advanced Security Testing Framework[/]")

    results = {
        'target': args.target,
        'recon': {},
        'ports': {},
        'vulnerabilities': [],
        'web_vulnerabilities': {},
        'enumeration': {},
        'aws_scan': {},
        'service_scan': {},
        'poc_generated': [],
        'xss_vulnerabilities': [],
        'sqli_vulnerabilities': [],
        'rce_vulnerabilities': []
    }

    with Progress() as progress:
        # Enumeration
        if not args.no_enum:
            enum_task = progress.add_task("[cyan]Running enumeration...", total=100)
            enumerator = Enumerator(args.target)
            results['enumeration'] = enumerator.enumerate(progress)
            progress.update(enum_task, completed=100)

        # AWS Resource Scanning
        if not args.no_aws:
            aws_task = progress.add_task("[cyan]Scanning AWS resources...", total=100)
            aws_scanner = AWSScanner(args.target)
            results['aws_scan'] = aws_scanner.scan_aws_resources()
            progress.update(aws_task, completed=100)

        # Reconnaissance
        recon_task = progress.add_task("[cyan]Running reconnaissance...", total=100)
        recon = Reconnaissance(args.target)
        results['recon'] = recon.gather_info()
        progress.update(recon_task, completed=100)

        # Port Scanning
        port_task = progress.add_task("[cyan]Scanning ports...", total=None)
        scanner = PortScanner(args.target)
        results['ports'] = scanner.scan_ports(args.ports, progress, port_task)

        # Service Scanning (SSH, FTP, RDP)
        service_task = progress.add_task("[cyan]Scanning services...", total=100)
        service_scanner = ServiceScanner(args.target)
        results['service_scan'] = service_scanner.scan_services(results['ports'])
        progress.update(service_task, completed=100)

        # Vulnerability Check
        if not args.no_vuln_check and results['ports']:
            vuln_task = progress.add_task("[cyan]Checking vulnerabilities...", total=100)
            vuln_db = VulnerabilityDB()
            results['vulnerabilities'] = vuln_db.check_vulnerabilities(args.target, results['ports'])
            progress.update(vuln_task, completed=100)

        # Web Vulnerability Scanning
        if not args.no_web_scan:
            web_vuln_task = progress.add_task("[cyan]Scanning for web vulnerabilities...", total=100)
            web_scanner = WebVulnScanner(args.target)
            web_results = web_scanner.scan()
            results['web_vulnerabilities'] = web_results
            if web_results:
                results['xss_vulnerabilities'] = web_results.get('xss', [])
                results['sqli_vulnerabilities'] = web_results.get('sqli', [])
                results['rce_vulnerabilities'] = web_results.get('rce', [])
            progress.update(web_vuln_task, completed=100)

        # Generate POCs
        poc_task = progress.add_task("[cyan]Generating proof of concepts...", total=100)
        poc_generator = POCGenerator(args.target)
        results['poc_generated'] = poc_generator.generate_pocs(results)
        progress.update(poc_task, completed=100)

    # Display formatted results
    display_scan_results(results)

    # Start interactive shell
    console.print("\n[info]Starting DefSec Interactive Shell...[/]")
    shell = DefSecShell(results)
    shell.cmdloop()

    # Generate Report if requested
    if args.output:
        reporter = Reporter(results)
        reporter.save_report(args.output)
        console.print(f"\n[success]Report saved to: {args.output}[/]")

    console.print("\n[bible]\"And whatsoever ye do, do it heartily, as to the Lord, and not unto men\" - Colossians 3:23[/bible]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[warning]Scan interrupted by user[/]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[error]An error occurred: {str(e)}[/]")
        sys.exit(1)