# 🔍 Python Port Scanner with Vulnerability Detection
A Python-based TCP port scanner that identifies open ports, grabs service banners, performs reverse DNS lookups, and optionally detects basic security misconfigurations on common services (HTTP, FTP, SSH, DNS).

## Features
✅ Custom TCP port scanning over a defined range  
✅ Reverse DNS lookup of the target  
✅ Banner grabbing for open ports  
✅ Optional vulnerability detection on well-known ports  
✅ Scan results saved to a local text file  

## Requirements
Python 3.x  
`requests` library (for vulnerability detection)  

Install required library:  
```bash```
pip install requests

## Usage
python3 scanner.py <target> [start_port] [end_port] [--vuln-check]

Examples:
Scan ports 20–80 on a domain:

python3 scanner.py example.com
Scan ports 1–1024 on a domain:

python3 scanner.py example.com 1 1024
Scan with vulnerability detection enabled:

python3 scanner.py example.com 1 1024 --vuln-check


Vulnerability Checks (--vuln-check)

If enabled, the script performs basic checks for:

HTTP Services (Ports 80, 443):

Missing security headers: Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-XSS-Protection
HTTP response status analysis
FTP (Port 21):

Detects vulnerable vsftpd 2.3.4 version (known backdoor vulnerability)
SSH (Port 22):

Flags outdated OpenSSH versions (e.g., OpenSSH_9.8)
DNS (Port 53):

Identifies open resolvers and exposed BIND banners
Output

Scan results are saved to a file named:
scan_results_<target>.txt

The report includes:

Target IP and reverse DNS (if available)
Scan start time
List of open ports
Banner information
Any detected vulnerabilities (if --vuln-check is used)
