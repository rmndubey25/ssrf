# Advanced SSRF Vulnerability Scanner

![SSRF Scanner](https://img.shields.io/badge/Security-SSRF%20Scanner-red)
![Python 3.7+](https://img.shields.io/badge/Python-3.7+-blue)
![License MIT](https://img.shields.io/badge/License-MIT-green)

A comprehensive and powerful tool for detecting Server-Side Request Forgery (SSRF) vulnerabilities in web applications. This scanner goes beyond basic testing by employing a wide range of techniques to discover and exploit potential SSRF vulnerabilities.

## Features

- **Deep Crawling**: Automatically discovers web pages and parameters through configurable depth crawling
- **Comprehensive Payload Testing**: Tests numerous SSRF vectors including:
  - Various localhost representations (127.0.0.1, localhost, 0, etc.)
  - IP obfuscation techniques (decimal, octal, hexadecimal)
  - Cloud metadata endpoints (AWS, GCP, Azure, DigitalOcean)
  - Protocol-based attacks (file://, dict://, gopher://)
  - DNS rebinding attack vectors
- **Advanced Detection Methods**:
  - Direct response analysis
  - Error message detection
  - Outbound callback detection for blind SSRF
  - Response timing analysis
- **Performance Optimized**:
  - Asynchronous request handling
  - Configurable concurrency
  - Rate limiting capabilities
- **Detailed Reporting**:
  - Severity classification (Critical, High, Medium, Low)
  - Evidence collection
  - JSON output for further processing

## Installation

```bash
# Clone the repository
git clone https://github.com/rmndubey25/ssrf.git
cd ssrf-scanner

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python ssrf_scanner.py https://target-website.com
```

### Advanced Options

```bash
# Specify output file
python ssrf_scanner.py https://target-website.com -o results.json

# Set crawling depth and concurrency
python ssrf_scanner.py https://target-website.com --depth 3 -c 20

# Enable callback server for blind SSRF detection
python ssrf_scanner.py https://target-website.com --callback --callback-port 8080

# Add authentication cookies
python ssrf_scanner.py https://target-website.com --cookies "session=abc123;user=admin"

# Use a proxy
python ssrf_scanner.py https://target-website.com --proxy http://127.0.0.1:8080
```

### Full Command Line Options

```
usage: ssrf_scanner.py [-h] [-o OUTPUT] [-c CONCURRENCY] [-t TIMEOUT] [-d DELAY]
                      [--depth DEPTH] [--no-verify-ssl] [--no-redirect]
                      [--callback] [--callback-host CALLBACK_HOST]
                      [--callback-port CALLBACK_PORT] [--cookies COOKIES]
                      [--user-agent USER_AGENT] [--proxy PROXY]
                      target

Advanced SSRF Vulnerability Scanner

positional arguments:
  target                Target URL to scan

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file for results (JSON)
  -c CONCURRENCY, --concurrency CONCURRENCY
                        Number of concurrent requests
  -t TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds
  -d DELAY, --delay DELAY
                        Delay between requests in seconds
  --depth DEPTH         Crawling depth
  --no-verify-ssl       Disable SSL verification
  --no-redirect         Don't follow redirects
  --callback            Enable callback server for blind SSRF detection
  --callback-host CALLBACK_HOST
                        Host for callback server
  --callback-port CALLBACK_PORT
                        Port for callback server
  --cookies COOKIES     Cookies to include with requests (format: name1=value1;name2=value2)
  --user-agent USER_AGENT
                        User-Agent string to use
  --proxy PROXY         Proxy URL (e.g., http://127.0.0.1:8080)
```

## Example Scan Output

```
======================================================
SSRF Scan Summary
======================================================
Target URL: https://example.com
Scan Duration: 45.23 seconds
URLs Scanned: 24
Parameters Tested: 67
Vulnerabilities Found: 3
======================================================

Vulnerabilities by Severity:
Critical: 1
High: 2
Medium: 0
Low: 0

------------------------------------------------------------
Top Vulnerable Endpoints:
1. https://example.com/search - 2 vulnerabilities
   [High] url - Basic localhost access
   [High] redirect_to - IP zero representation
2. https://example.com/api/fetch - 1 vulnerability
   [Critical] source - AWS metadata service

Detailed results saved to: results.json
```

## Responsible Usage

This tool is designed for security professionals to test applications they have permission to scan. Always ensure you have proper authorization before scanning any website. Unauthorized scanning may be illegal and unethical.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Disclaimer

This tool is provided for educational and professional security testing purposes only. The author is not responsible for any misuse or damage caused by this program.
