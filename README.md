# IoTSentinel-Security
IoTSentinel is a network security tool with a modern CLI for scanning IoT devices, identifying open ports, and detecting vulnerabilities. The interface features a welcome banner, prompts for network scanning, detailed vulnerability information, and options to generate reports, visualize results, or rescan the network.

Features

Network Scanning: Identify all active IoT devices within a specified IP range and detect open ports.
Vulnerability Detection: Check for known vulnerabilities using the National Vulnerability Database (NVD).
Detailed Reports: Generate HTML and CSV reports with detailed information about the devices, services, and vulnerabilities found.
Interactive Visualization: Visualize vulnerable devices on your network with detailed information about each vulnerability.
User-Friendly CLI: Simple and intuitive CLI with interactive prompts for easy use.

Installation

Prerequisites
Python 3.6 or later
pip for managing Python packages


Setup
Clone the repository to your local machine:

git clone https://github.com/NotoriousX/IoTSentinel.git

cd IoTSentinel

python3 iot_sentinel.py


Usage

Once you run the script, you'll be greeted with a welcome banner and prompted to scan your network. After the scan, you'll have the option to generate reports, visualize vulnerabilities, or rescan the network.

Example Workflow
Start the Network Scan: Enter the IP range and ports to scan.

View Vulnerability Details: After the scan, any detected vulnerabilities are displayed with details.

Generate Reports: Choose to generate an HTML or CSV report for detailed documentation.

Visualize Vulnerabilities: Use the interactive visualization to see which devices are vulnerable and which services are affected.


Menu Options
Rescan the Network: Start a new scan if you’ve added new devices or want to refresh the data.
Generate HTML Report: Create a detailed HTML report that you can view in any web browser.
Generate CSV Report: Export the scan results to a CSV file for further analysis.
Visualize Vulnerabilities: Generate an interactive chart showing all vulnerable devices and their details.
Exit: Close the program.



Please scan the network first.
Enter the IP range to scan (e.g., 192.168.1.0/24): 192.168.1.0/24
Enter the ports to scan (e.g., 80, 22-80): 22,80
Scanning the network 192.168.1.0/24 for IoT devices on ports 22,80...

Checking for known vulnerabilities...

Vulnerabilities found:

Device: 192.168.1.10:80 (http)
  - CVE-2021-XXXXX: Some description of the vulnerability.
  - CVE-2021-YYYYY: Another vulnerability description.

Choose what you want to do next:
1. Rescan the network
2. Generate HTML report
3. Generate CSV report
4. Visualize vulnerabilities
5. Exit

Contributing

We welcome contributions from the community. Please feel free to submit issues or pull requests to help improve IoTSentinel.

License

This project is licensed under the MIT License.

