import socket
import whois
import dns.resolver
from rich.console import Console

console = Console()

class Reconnaissance:
    def __init__(self, target):
        self.target = target
        self.results = {
            'ip_addresses': [],
            'dns_records': {},
            'whois_info': {}
        }

    def gather_info(self):
        try:
            # Resolve IP addresses
            ips = socket.gethostbyname_ex(self.target)
            self.results['ip_addresses'] = ips[2]

            # Get DNS records
            record_types = ['A', 'MX', 'NS', 'TXT']
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(self.target, record_type)
                    self.results['dns_records'][record_type] = [str(rdata) for rdata in answers]
                except Exception:
                    self.results['dns_records'][record_type] = []

            # Get WHOIS information
            try:
                w = whois.whois(self.target)
                self.results['whois_info'] = {
                    'registrar': w.registrar,
                    'creation_date': w.creation_date,
                    'expiration_date': w.expiration_date,
                    'name_servers': w.name_servers
                }
            except Exception:
                console.print("[warning]WHOIS information unavailable[/]")

        except Exception as e:
            console.print(f"[error]Error during reconnaissance: {str(e)}[/]")

        return self.results
