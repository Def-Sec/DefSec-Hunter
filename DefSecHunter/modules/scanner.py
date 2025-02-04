"""Port Scanner Module for DefSec"""
import socket
import concurrent.futures
from rich.console import Console
import yaml
import time
from rich.progress import Progress, TaskID
import re
import requests

console = Console()

class PortScanner:
    def __init__(self, target):
        self.target = target
        self.open_ports = {}
        self.results = {}
        # Load config with optimized scanning options
        try:
            with open('config/default.yaml', 'r') as f:
                self.config = yaml.safe_load(f)
        except Exception:
            self.config = {
                'scan': {'max_threads': 50, 'timeout': 1},  # Reduced timeout for faster scanning
                'rate_limit': {'requests_per_second': 100, 'pause_between_scans': 0.1}  # Optimized rate limiting
            }

    def port_scan(self, port):
        """Optimized port scanning with efficient service detection"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.config['scan']['timeout'])
                result = sock.connect_ex((self.target, port))

                if result == 0:
                    service = self._identify_service(port)
                    version = ""
                    banner = self._get_service_banner(port)
                    if banner:
                        version = self._extract_version(banner)

                    # Store port information
                    self.open_ports[port] = {
                        'service': service,
                        'version': version,
                        'state': 'open',
                        'protocol': 'tcp'
                    }

        except (socket.timeout, socket.gaierror, ConnectionRefusedError):
            pass
        except Exception as e:
            console.print(f"[warning]Error scanning port {port}: {str(e)}[/]")

    def _get_service_banner(self, port):
        """Quick service banner grabbing"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2)  # Reduced timeout
                s.connect((self.target, port))

                # Send appropriate probe based on port
                probes = {
                    80: b"GET / HTTP/1.0\r\n\r\n",
                    443: b"GET / HTTP/1.0\r\n\r\n",
                    22: b"SSH-2.0-OpenSSH_8.4\r\n",
                    21: b"USER anonymous\r\n",
                    25: b"EHLO defsec.test\r\n",
                }

                s.send(probes.get(port, b"\r\n"))
                return s.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            return ""

    def _identify_service(self, port, banner=""):
        """Basic service identification"""
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            80: 'http', 443: 'https', 3306: 'mysql', 5432: 'postgresql',
            27017: 'mongodb', 6379: 'redis', 8080: 'http-alt'
        }
        return common_ports.get(port, "unknown")

    def _extract_version(self, banner):
        """Quick version extraction"""
        version_pattern = r'(?:version |ver |v)(\d+\.[\d\.]+\w*)'
        match = re.search(version_pattern, banner, re.IGNORECASE)
        return match.group(1) if match else ""

    def parse_port_range(self, port_range):
        """Efficient port range parsing"""
        ports = []
        try:
            for part in port_range.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    if 1 <= start <= end <= 65535:
                        ports.extend(range(start, end + 1))
                else:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.append(port)
            return ports or list(range(1, 1001))  # Default to 1-1000
        except:
            return list(range(1, 1001))  # Default to 1-1000 on error

    def scan_ports(self, port_range, progress: Progress, task_id: TaskID):
        """Optimized port scanning with better progress tracking"""
        ports = self.parse_port_range(port_range)
        total_ports = len(ports)
        batch_size = 100  # Increased batch size
        completed = 0

        try:
            progress.update(task_id, total=total_ports)

            # Process ports in batches
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['scan']['max_threads']) as executor:
                for i in range(0, total_ports, batch_size):
                    batch = ports[i:i + batch_size]

                    # Submit batch of ports for scanning
                    futures = [executor.submit(self.port_scan, port) for port in batch]

                    # Wait for batch completion with timeout
                    done, not_done = concurrent.futures.wait(
                        futures,
                        timeout=self.config['scan']['timeout'] * 2
                    )

                    # Cancel any remaining scans
                    for future in not_done:
                        future.cancel()

                    # Update progress
                    completed += len(done)
                    progress.update(task_id, completed=completed)

                    # Brief pause between batches
                    time.sleep(self.config['rate_limit']['pause_between_scans'])

            return self.open_ports

        except Exception as e:
            console.print(f"[error]Error during port scanning: {str(e)}[/]")
            return self.open_ports