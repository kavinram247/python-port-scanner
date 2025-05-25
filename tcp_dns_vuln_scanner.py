#!/bin/python3
import sys
import socket
from datetime import datetime
import argparse
import requests

# Initialize argument parser
parser = argparse.ArgumentParser(description="Port scanner with Reverse DNS Lookup and Basic Vulnerability Scanning")

# Define command-line arguments
parser.add_argument("target", help="The target IP or domain to scan (e.g., example.com or 93.184.216.34)")
parser.add_argument("start_port", nargs="?", default=20, type=int, help="The starting port number for scanning (default is 20)")
parser.add_argument("end_port", nargs="?", default=80, type=int, help="The ending port number for scanning (default is 80)")
parser.add_argument("--vuln-check", action="store_true", help="Perform basic vulnerability checks on open ports")

# Parse arguments
args = parser.parse_args()

# If -help or no arguments are passed, show help
if len(sys.argv) == 1 or '-help' in sys.argv or '--help' in sys.argv:
    parser.print_help()
    sys.exit()

# Define the target
target = socket.gethostbyname(args.target)  # Resolve hostname to IP

# Perform Reverse DNS lookup
try:
    reverse_dns = socket.gethostbyaddr(target)
    hostname = reverse_dns[0]  # The first element is the hostname
    print(f"Reverse DNS lookup successful: {hostname}")
except socket.herror:
    hostname = None
    print(f"Reverse DNS lookup failed for {target}, no hostname available")

# Pretty banner
print("-" * 50)
print(f"Scanning Target: {target}")
# Ensure the time is printed correctly
print("Time Started: " + str(datetime.now()))  # Using str() to ensure the datetime is a string
print(f"Scanning ports from {args.start_port} to {args.end_port}")
print("-" * 50)

# Save results to a file
filename = f"scan_results_{target}.txt"
with open(filename, "w") as file:
    file.write(f"Scan report for {target}\n")
    file.write("Time Started: " + str(datetime.now()) + "\n\n")
    if hostname:
        file.write(f"Reverse DNS: {hostname}\n\n")
    else:
        file.write(f"Reverse DNS lookup failed for {target}\n\n")

# Function to perform basic vulnerability checks
def vuln_check(port, target):
    # For HTTP service (port 80, 443, etc.)
    if port == 80 or port == 443:
        try:
            response = requests.get(f"http://{target}:{port}", timeout=2)
            headers = response.headers

            # Check for common vulnerabilities in HTTP headers
            print(f"Checking for vulnerabilities on port {port} (HTTP)...")
            if "Strict-Transport-Security" not in headers:
                print("Vulnerability: Missing Strict-Transport-Security header.")
            if "X-Content-Type-Options" not in headers:
                print("Vulnerability: Missing X-Content-Type-Options header.")
            if "X-XSS-Protection" not in headers:
                print("Vulnerability: Missing X-XSS-Protection header.")
            if "Content-Security-Policy" not in headers:
                print("Vulnerability: Missing Content-Security-Policy header.")
            if response.status_code != 200:
                print(f"Potential issue: Received status code {response.status_code} on port {port}")
        except requests.RequestException:
            print(f"Error checking vulnerabilities on port {port}")
    
    # For FTP service (port 21)
    elif port == 21:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(2)
            s.connect((target, port))
            banner = s.recv(1024).decode()
            if "vsftpd" in banner:
                if "vsftpd 2.3.4" in banner:
                    print("Vulnerability: Found vulnerable vsftpd 2.3.4 (Backdoor vulnerability).")
            s.close()
        except:
            print("Error checking FTP banner.")
    
    # For SSH service (port 22)
    elif port == 22:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(2)
            s.connect((target, port))
            banner = s.recv(1024).decode()
            if "OpenSSH_9.8" in banner:
                print(f"Vulnerability: Found outdated OpenSSH version on port {port}.")
            s.close()
        except:
            print("Error checking SSH banner.")

    # For DNS service (port 53)
    elif port == 53:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(2)
            s.connect((target, port))
            banner = s.recv(1024).decode()
            if "BIND" in banner:
                print(f"Vulnerability: Found open DNS resolver on port {port}.")
            s.close()
        except:
            print("Error checking DNS banner.")

# Scan ports and check for vulnerabilities
try:
    for port in range(args.start_port, args.end_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        
        # Attempt to connect to the port
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is open")

            # Perform vulnerability check if the flag is set
            if args.vuln_check:
                vuln_check(port, target)

            # Try to grab the service banner (for HTTP, FTP, etc.)
            try:
                s.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                banner = s.recv(1024).decode().strip()
                print(f"Banner for port {port}: {banner}")
            except:
                print(f"Port {port} is open - No banner available")

            # Save results to file
            with open(filename, "a") as file:
                file.write(f"Port {port} is open\n")
                file.write(f"Banner: {banner}\n")
        
        s.close()

except KeyboardInterrupt:
    print("\nExiting program")
    sys.exit()
except socket.gaierror:
    print("Hostname could not be resolved")
    sys.exit()
except socket.error:
    print("Couldn't connect to server")
    sys.exit()

# Completion message
print("-" * 50)
print(f"Scan complete. Results saved to {filename}")
print("-" * 50)
