import nmap
import requests

# Scan for open ports
def scan_ports(target):
    nm = nmap.PortScanner()
    nm.scan(target, '1-1024')  # Scans ports 1 to 1024
    open_ports = []
    
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                state = nm[host][proto][port]['state']
                if state == 'open':
                    open_ports.append(port)
    
    return open_ports

# Check for outdated software versions
def check_outdated_software(software_list):
    outdated_software = []
    for software in software_list:
        # Dummy check for outdated software (this should be more advanced with APIs or CVE databases)
        if software in ['nginx/1.10', 'apache/2.2']:
            outdated_software.append(software)
    return outdated_software

# Check for misconfigurations (e.g., open HTTP headers)
def check_misconfigurations(target_url):
    misconfigurations = []
    
    try:
        response = requests.get(target_url)
        
        # Example check for misconfigured headers
        if 'X-Content-Type-Options' not in response.headers:
            misconfigurations.append("Missing 'X-Content-Type-Options' header.")
        
        if 'Strict-Transport-Security' not in response.headers:
            misconfigurations.append("Missing 'Strict-Transport-Security' header.")
    except Exception as e:
        misconfigurations.append(f"Error accessing {target_url}: {str(e)}")
    
    return misconfigurations

# Test the vulnerability scanner
if __name__ == "__main__":
    target = input("Enter target IP or domain: ")
    target_url = f"http://{target}" if not target.startswith("http") else target
    
    print(f"Scanning {target} for vulnerabilities...\n")
    
    # Scan for open ports
    open_ports = scan_ports(target)
    if open_ports:
        print(f"Open ports found: {open_ports}")
    else:
        print("No open ports found.")
    
    # Check for outdated software (dummy data used here)
    software_list = ['nginx/1.10', 'apache/2.2']  # Simulated software versions
    outdated_software = check_outdated_software(software_list)
    if outdated_software:
        print(f"Outdated software found: {outdated_software}")
    else:
        print("No outdated software detected.")
    
    # Check for misconfigurations
    misconfigurations = check_misconfigurations(target_url)
    if misconfigurations:
        print(f"Misconfigurations found: {misconfigurations}")
    else:
        print("No misconfigurations detected.")
