import subprocess
import sys
import argparse
import logging

# Function to install required packages
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# List of required packages
required_packages = [
    "python-nmap",
    "requests",
    "plotly",
    "termcolor",
    "tqdm"
]

# Install each package if not already installed
for package in required_packages:
    try:
        __import__(package.replace("-", "_"))
    except ImportError:
        print(f"{package} not found. Installing...")
        install(package)

import nmap
import requests
import plotly.graph_objects as go
import csv
import os
import time
from termcolor import colored
from tqdm import tqdm

# Set up logging
logging.basicConfig(filename='iot_sentinel.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')

def display_banner():
    banner = colored(r"""
    /\_/\
   ( o.o )
    > ^ <
    """, 'cyan')
    print(banner)
    print(colored("Welcome to IoTSentinel", "yellow"))
    logging.info("Displayed banner")

def scan_network(ip_range, ports):
    nm = nmap.PortScanner()
    try:
        print(colored("Starting network scan...", "green"))
        nm.scan(hosts=ip_range, arguments=f'-p {ports} --open')
        logging.info(f"Scanning network {ip_range} on ports {ports}")
    except Exception as e:
        logging.error(f"Network scanning error: {e}")
        sys.exit(1)
    
    devices = []
    for host in tqdm(nm.all_hosts(), desc="Processing hosts", ncols=100):
        for port in nm[host]['tcp']:
            if nm[host]['tcp'][port]['state'] == 'open':
                os_info = nm[host].get('osclass', [{'osfamily': 'Unknown'}])
                devices.append({
                    'ip': host,
                    'port': port,
                    'os': os_info[0]['osfamily'] if os_info != 'Unknown' else 'Unknown',
                    'service': nm[host]['tcp'][port]['name']
                })
    return devices

def get_cve_data(cpe):
    url = f'https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={cpe}'
    try:
        response = requests.get(url)
        response.raise_for_status()
        logging.info(f"Fetched CVE data for {cpe}")
        return response.json().get('result', {}).get('CVE_Items', [])
    except requests.RequestException as e:
        logging.error(f"Error fetching CVE data: {e}")
        return []

def check_vulnerabilities(devices):
    print(colored("Checking for known vulnerabilities...", "yellow"))
    for device in devices:
        cpe = f'cpe:/o:{device["os"]}'  # Simplification; normally you'd need the exact CPE string.
        cve_data = get_cve_data(cpe)
        device['vulnerabilities'] = cve_data
    if devices:
        print(colored("Vulnerabilities found:", "red"))
        for device in devices:
            if device['vulnerabilities']:
                print(f"\nDevice: {device['ip']}:{device['port']} ({device['service']})")
                for vulnerability in device['vulnerabilities']:
                    print(f"  - {vulnerability['cve']['CVE_data_meta']['ID']}: {vulnerability['cve']['description']['description_data'][0]['value']}")
    else:
        print(colored("No vulnerabilities found.", "green"))
    return devices

def generate_html_report(devices, filename='iot_report.html'):
    with open(filename, 'w') as f:
        f.write("<html><head><title>IoTSentinel Report</title></head><body>")
        f.write("<h1>IoTSentinel Scan Report</h1>")
        f.write("<table border='1'><tr><th>IP</th><th>Port</th><th>Vulnerabilities</th></tr>")
        for device in devices:
            f.write(f"<tr><td>{device['ip']}</td><td>{device['port']}</td><td>")
            for vulnerability in device['vulnerabilities']:
                f.write(f"<p>{vulnerability['cve']['CVE_data_meta']['ID']}: {vulnerability['cve']['description']['description_data'][0]['value']}</p>")
            f.write("</td></tr>")
        f.write("</table></body></html>")
    logging.info(f"Generated HTML report: {filename}")

def generate_csv_report(devices, filename='iot_report.csv'):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['IP', 'Port', 'Service', 'OS', 'Vulnerability ID', 'Description']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for device in devices:
            for vulnerability in device['vulnerabilities']:
                writer.writerow({
                    'IP': device['ip'],
                    'Port': device['port'],
                    'Service': device['service'],
                    'OS': device['os'],
                    'Vulnerability ID': vulnerability['cve']['CVE_data_meta']['ID'],
                    'Description': vulnerability['cve']['description']['description_data'][0]['value']
                })
    logging.info(f"Generated CSV report: {filename}")

def visualize_vulnerabilities(devices):
    fig = go.Figure()

    for device in devices:
        if device['vulnerabilities']:
            vulnerabilities = len(device['vulnerabilities'])
            description = "<br>".join([
                f"{v['cve']['CVE_data_meta']['ID']}: {v['cve']['description']['description_data'][0]['value']}"
                for v in device['vulnerabilities']
            ])
            fig.add_trace(go.Scatter(
                x=[device['ip']],
                y=[f"Port: {device['port']} ({device['service']})"],
                text=f"{vulnerabilities} vulnerabilities<br>{description}",
                mode='markers',
                marker=dict(size=vulnerabilities*10, color='red'),
                hoverinfo='text'
            ))

    fig.update_layout(
        title="Vulnerable IoT Devices",
        xaxis_title="Device IP",
        yaxis_title="Port and Service",
        showlegend=False
    )

    fig.show()

def main():
    display_banner()
    
    while True:
        # Ensure the user first performs a scan
        print(colored("Please scan the network first.", "yellow"))
        ip_range = input(colored("Enter the IP range to scan (e.g., 192.168.1.0/24): ", "cyan"))
        ports = input(colored("Enter the ports to scan (e.g., 80, 22-80): ", "cyan"))
        print(f"Scanning the network {ip_range} for IoT devices on ports {ports}...")
        devices = scan_network(ip_range, ports)
        
        if not devices:
            print(colored("No IoT devices found.", "red"))
            logging.info("No IoT devices found")
            sys.exit(1)
        
        vulnerable_devices = check_vulnerabilities(devices)
        print(colored("Scan complete.", "green"))
        
        while True:
            # Presenting a menu for user choices after the scan
            print(colored("Choose what you want to do next:", "yellow"))
            print(colored("1. Rescan the network", "green"))
            print(colored("2. Generate HTML report", "green"))
            print(colored("3. Generate CSV report", "green"))
            print(colored("4. Visualize vulnerabilities", "green"))
            print(colored("5. Exit", "red"))

            choice = input(colored("Enter your choice (1-5): ", "cyan"))

            if choice == '1':
                break  # Breaks the inner loop, allowing the user to rescan
            elif choice == '2':
                generate_html_report(vulnerable_devices)
                print(colored(f"HTML report generated: {os.path.abspath('iot_report.html')}", "green"))
            elif choice == '3':
                generate_csv_report(vulnerable_devices)
                print(colored(f"CSV report generated: {os.path.abspath('iot_report.csv')}", "green"))
            elif choice == '4':
                visualize_vulnerabilities(vulnerable_devices)
            elif choice == '5':
                print(colored("Exiting.", "red"))
                sys.exit(0)
            else:
                print(colored("Invalid choice. Please try again.", "red"))

if __name__ == "__main__":
    main()
