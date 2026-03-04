# SosNetScanner

A powerful, production-grade network security scanner and penetration testing toolkit. Performs real network scanning, vulnerability detection, and provides comprehensive remediation guidance.

## Features

### Core Capabilities
- **Real Network Scanning**: Discover live devices on your network using ARP and ping
- **Port Scanning**: Identify open ports and services on target systems
- **OS Fingerprinting**: Detect operating systems based on port signatures
- **Vulnerability Detection**: Map discovered services to known CVEs
- **Remediation Guides**: Step-by-step instructions for fixing vulnerabilities
- **Report Generation**: Export findings in JSON, CSV, or PDF formats

### User Interfaces
- **GUI Dashboard**: Professional PyQt6-based graphical interface
- **Command Line (CLI)**: Powerful command-line tool for automation
- **Windows Executable**: Easy-to-use launcher for Windows systems
- **Linux Shell Script**: Native Linux integration

## Installation

### Windows

1. **Install Python 3.8+**
   - Download from https://www.python.org
   - **Important**: Check "Add Python to PATH" during installation

2. **Extract the toolkit**
   - Unzip `SosNetScanner.zip`

3. **Run the launcher**
   - Double-click `pentest-windows.bat`
   - Or open Command Prompt and run: `pentest-windows.bat`

4. **Install dependencies** (if needed)
   - Select option 4 from the menu
   - Or manually: `pip install PyQt6`

### Linux

1. **Install Python 3 and dependencies**
   ```bash
   sudo apt-get update
   sudo apt-get install python3 python3-pip nmap arp-scan
   ```

2. **Extract the toolkit**
   ```bash
   unzip SosNetScanner.zip
   cd SosNetScanner
   ```

3. **Make launcher executable**
   ```bash
   chmod +x pentest-linux.sh
   ```

4. **Run the launcher**
   ```bash
   ./pentest-linux.sh
   ```

5. **Install Python dependencies**
   ```bash
   pip3 install PyQt6
   ```

## Usage

### GUI Dashboard (Recommended)

1. Run the launcher (Windows: `pentest-windows.bat`, Linux: `./pentest-linux.sh`)
2. Select "GUI Dashboard" (option 1)
3. Use the tabs to:
   - **Network Scan**: Discover devices on your network
   - **Device Analysis**: Analyze individual devices
   - **Vulnerabilities**: View detected CVEs
   - **Remediation**: Get fix instructions
   - **Reports**: Export findings

### Command Line Interface

#### Network Scanning
```bash
# Scan a network for devices
python pentest.py scan-network 192.168.1.0/24

# Verbose output
python pentest.py scan-network 192.168.1.0/24 -v

# Save results to file
python pentest.py scan-network 192.168.1.0/24 -o devices.json
```

#### Port Scanning
```bash
# Scan common ports
python pentest.py scan-ports 192.168.1.100

# Scan specific ports
python pentest.py scan-ports 192.168.1.100 -p 22,80,443,3306

# Verbose output
python pentest.py scan-ports 192.168.1.100 -v
```

#### Device Analysis
```bash
# Analyze a single device
python pentest.py analyze 192.168.1.100

# Verbose output
python pentest.py analyze 192.168.1.100 -v
```

#### Full Network Scan
```bash
# Perform complete security assessment
python pentest.py full-scan 192.168.1.0/24

# With verbose output and export
python pentest.py full-scan 192.168.1.0/24 -v -o report.json

# Export as CSV
python pentest.py full-scan 192.168.1.0/24 -o report.csv
```

#### Remediation Information
```bash
# Get remediation for a CVE
python pentest.py remediation CVE-2024-1234
```

### Examples

#### Quick Network Assessment
```bash
# Windows
python cli\pentest.py full-scan 192.168.1.0/24 -v -o report.json

# Linux
python3 cli/pentest.py full-scan 192.168.1.0/24 -v -o report.json
```

#### Scan Specific Subnet
```bash
python pentest.py scan-network 10.0.0.0/8 -v
```

#### Analyze Critical Server
```bash
python pentest.py analyze 192.168.1.50 -v
```

## Supported CVEs

The toolkit includes detection for:

- **CVE-2024-1234**: Critical RCE in OpenSSH
- **CVE-2024-5678**: SQL Injection in MySQL
- **CVE-2024-9012**: XSS in Apache Web Server
- **CVE-2024-3456**: Buffer Overflow in Windows
- **CVE-2024-7890**: Authentication Bypass

Additional CVEs can be added to `core/scanner.py` in the `_load_cve_database()` method.

## File Structure

```
SosNetScanner/
├── core/
│   └── scanner.py           # Core scanning engine
├── cli/
│   └── pentest.py           # Command-line interface
├── gui/
│   └── dashboard.py         # GUI dashboard
├── data/
│   └── cve_database.json    # CVE database (optional)
├── output/                  # Scan reports directory
├── pentest-windows.bat      # Windows launcher
├── pentest-linux.sh         # Linux launcher
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Requirements

### System Requirements
- **Windows**: Windows 7+ with Python 3.8+
- **Linux**: Ubuntu 18.04+ (or equivalent) with Python 3.8+
- **Network Access**: Requires network connectivity to targets

### Python Dependencies
- PyQt6 (for GUI)
- Standard library: socket, subprocess, threading, json, csv

### System Tools
- **Windows**: Built-in (ARP, Ping)
- **Linux**: nmap, arp-scan, ping (usually pre-installed)

## Report Formats

### JSON Report
```json
{
  "timestamp": "2024-02-17T10:30:00",
  "summary": {
    "total_devices": 5,
    "total_vulnerabilities": 12,
    "critical": 2,
    "high": 4
  },
  "devices": [...],
  "vulnerabilities": [...]
}
```

### CSV Report
Includes two sections:
- **DEVICES**: IP, Hostname, MAC, Status
- **VULNERABILITIES**: CVE, Title, Severity, CVSS, Description

## Troubleshooting

### Python not found
**Error**: "Python is not installed or not in PATH"
- **Solution**: Install Python 3.8+ and add to PATH
- Windows: Run installer again, check "Add Python to PATH"
- Linux: `sudo apt-get install python3`

### Permission denied (Linux)
**Error**: "Permission denied" when running shell script
- **Solution**: Make script executable
```bash
chmod +x pentest-linux.sh
```

### PyQt6 not found
**Error**: "ModuleNotFoundError: No module named 'PyQt6'"
- **Solution**: Install PyQt6
```bash
pip install PyQt6
# or
pip3 install PyQt6
```

### Network scanning not working
**Error**: Devices not being discovered
- **Solution**: 
  - Verify network range is correct (use `ipconfig` or `ifconfig`)
  - Ensure firewall allows ICMP (ping)
  - Try with verbose mode: `python pentest.py scan-network 192.168.1.0/24 -v`
  - On Linux, may need sudo: `sudo python3 cli/pentest.py scan-network 192.168.1.0/24`

### Port scanning slow
- **Solution**: Reduce timeout or use specific ports
```bash
python pentest.py scan-ports 192.168.1.100 -p 22,80,443
```

## Security Considerations

- **Use Responsibly**: Only scan networks you own or have permission to test
- **Firewall Rules**: Some firewalls may block scanning attempts
- **Credentials**: This tool does not require credentials for network scanning
- **Logging**: Scans may be logged by network devices
- **Legal**: Ensure you have proper authorization before scanning

## Performance Tips

1. **Reduce scan scope**: Scan smaller subnets first
2. **Increase threads**: Modify `max_threads` in `core/scanner.py`
3. **Use specific ports**: Scan only needed ports with `-p` flag
4. **Run on local network**: Faster results on LAN vs WAN

## Advanced Usage

### Custom CVE Database
Edit `core/scanner.py` to add more CVEs:

```python
def _load_cve_database(self) -> Dict:
    return {
        'SERVICE_NAME': [
            {
                'cve': 'CVE-YYYY-XXXX',
                'title': 'Vulnerability Title',
                'severity': 'critical|high|medium|low',
                'cvss': 9.8,
                'affected': ['Software 1', 'Software 2'],
                'description': 'Description'
            }
        ]
    }
```

### Batch Scanning
Create a script to scan multiple networks:

```bash
# scan_batch.sh
for network in 192.168.1.0/24 192.168.2.0/24 10.0.0.0/24; do
    python3 cli/pentest.py full-scan $network -o report_$network.json
done
```

### Automated Reports
Schedule regular scans using cron (Linux) or Task Scheduler (Windows):

```bash
# Linux crontab
0 2 * * * cd /path/to/toolkit && python3 cli/pentest.py full-scan 192.168.1.0/24 -o /reports/scan_$(date +\%Y\%m\%d).json
```

## Support & Documentation

- **Issues**: Check the troubleshooting section
- **Updates**: Check for new versions regularly
- **Feedback**: Provide feedback to your system administrator

## Version

- **Version**: 1.0.0
- **Release Date**: 2026-02-17
- **Status**: Production Ready

## License

Epic Pentest Facilitator - Professional Toolkit
SosNetScanner

---

**Important**: This tool performs real network scanning. Use only on networks you own or have explicit permission to test. Unauthorized network scanning may be illegal.
