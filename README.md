# DefSec Security Testing Tool

A professional security testing tool for bug bounty research.

## Installation

### Required Dependencies
To install all required dependencies on your Kali Linux machine, run this specific pip command:

```bash
pip install "urllib3<2.0.0" paramiko==3.4.0 pyyaml==6.0.1 requests==2.31.0 rich==13.7.0 beautifulsoup4==4.12.2 boto3==1.34.14 dnspython==2.4.2 cryptography==41.0.7 python-whois==0.8.0
```

Or install them individually:
- urllib3<2.0.0 (Required by requests)
- paramiko==3.4.0 (SSH scanning)
- pyyaml==6.0.1 (Configuration files)
- requests==2.31.0 (HTTP requests)
- rich==13.7.0 (Terminal UI)
- beautifulsoup4==4.12.2 (HTML parsing)
- boto3==1.34.14 (AWS scanning)
- dnspython==2.4.2 (DNS operations)
- cryptography==41.0.7 (Required by paramiko)
- python-whois==0.8.0 (WHOIS lookups)

## Usage

Basic usage:
```bash
python defsec.py -t target.com
```

Options:
- `-t, --target`: Target domain or IP address (Required)
- `-p, --ports`: Port range to scan (default: 1-1000)
- `-o, --output`: Output report file
- `--no-vuln-check`: Skip vulnerability checks
- `--no-web-scan`: Skip web vulnerability scanning
- `--no-enum`: Skip enumeration phase
- `--no-aws`: Skip AWS resource scanning

## Features

- Service Scanning (SSH, FTP, RDP)
- Detailed POC Generation
- AWS Resource Scanning
- Subdomain Enumeration
- Technology Detection
- Port Scanning
- Web Vulnerability Scanning
- Comprehensive Reporting

## Output

The tool provides detailed output including:
- Service vulnerabilities with severity levels
- Exploitation guides with step-by-step instructions
- Mitigation recommendations
- AWS resource findings
- Port scan results
- Enumeration results

## Note

This tool is intended for legitimate security testing purposes only. Always ensure you have proper authorization before testing any targets.