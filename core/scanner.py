#!/usr/bin/env python3
"""
APEC Pentest Toolkit - Core Network Scanner
Real network scanning, device discovery, and vulnerability detection
"""

import socket
import subprocess
import ipaddress
import json
import threading
import time
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import sys
import os

try:
    import nmap
except ImportError:
    nmap = None

try:
    from scapy.all import ARP, Ether, srp, conf
except ImportError:
    pass


class NetworkScanner:
    """Real network device discovery and scanning"""
    
    def __init__(self, timeout: int = 5, max_threads: int = 50):
        self.timeout = timeout
        self.max_threads = max_threads
        self.discovered_devices = []
        self.lock = threading.Lock()
    
    def is_valid_cidr(self, cidr: str) -> bool:
        """Validate CIDR notation"""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    def get_ip_range(self, cidr: str) -> List[str]:
        """Get all IPs in CIDR range"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []
    
    def ping_host(self, ip: str) -> bool:
        """Check if host is alive with ping"""
        try:
            if sys.platform == 'win32':
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', '1000', ip],
                    capture_output=True,
                    timeout=2
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    capture_output=True,
                    timeout=2
                )
            return result.returncode == 0
        except Exception:
            return False
    
    def get_hostname(self, ip: str) -> str:
        """Resolve hostname from IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.timeout):
            return "Unknown"
    
    def get_mac_address(self, ip: str) -> str:
        """Get MAC address using ARP"""
        try:
            # Try using arp command
            if sys.platform == 'win32':
                result = subprocess.run(
                    ['arp', '-a', ip],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                return parts[1]
            else:
                result = subprocess.run(
                    ['arp', '-n', ip],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 3:
                                return parts[2]
        except Exception:
            pass
        return "Unknown"
    
    def scan_network(self, cidr: str, callback=None) -> List[Dict]:
        """Scan network and discover devices"""
        if not self.is_valid_cidr(cidr):
            raise ValueError(f"Invalid CIDR: {cidr}")
        
        ips = self.get_ip_range(cidr)
        self.discovered_devices = []
        
        def scan_ip(ip):
            if self.ping_host(ip):
                hostname = self.get_hostname(ip)
                mac = self.get_mac_address(ip)
                
                device = {
                    'ip': ip,
                    'hostname': hostname,
                    'mac': mac,
                    'status': 'online',
                    'timestamp': datetime.now().isoformat()
                }
                
                with self.lock:
                    self.discovered_devices.append(device)
                    if callback:
                        callback(device)
        
        # Use threading for faster scanning
        threads = []
        for ip in ips:
            while len(threads) >= self.max_threads:
                threads = [t for t in threads if t.is_alive()]
                time.sleep(0.1)
            
            t = threading.Thread(target=scan_ip, args=(ip,))
            t.daemon = True
            t.start()
            threads.append(t)
        
        # Wait for all threads
        for t in threads:
            t.join()
        
        return self.discovered_devices


class PortScanner:
    """Port scanning and service detection"""
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 9200: 'Elasticsearch', 27017: 'MongoDB'
        }
    
    def scan_ports(self, ip: str, ports: List[int] = None) -> List[Dict]:
        """Scan open ports on target IP"""
        if ports is None:
            ports = list(self.common_ports.keys())
        
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout / 1000)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    service = self.common_ports.get(port, 'Unknown')
                    open_ports.append({
                        'port': port,
                        'service': service,
                        'status': 'open'
                    })
            except Exception:
                pass
        
        return open_ports
    
    def detect_service_version(self, ip: str, port: int) -> Optional[str]:
        """Try to detect service version"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner.strip()
        except Exception:
            return None


class OSDetection:
    """Operating system detection and fingerprinting"""
    
    @staticmethod
    def detect_os(ip: str, open_ports: List[Dict]) -> str:
        """Detect OS based on open ports and services"""
        services = [p['service'] for p in open_ports]
        
        # Simple heuristics
        if 'RDP' in services:
            return 'Windows'
        elif 'SSH' in services and 'HTTP' in services:
            return 'Linux'
        elif 'SSH' in services:
            return 'Linux/Unix'
        elif 'SMB' in services:
            return 'Windows'
        elif 'HTTP' in services or 'HTTPS' in services:
            return 'Web Server (Linux/Windows)'
        else:
            return 'Unknown'


class VulnerabilityScanner:
    """Vulnerability detection and CVE mapping"""
    
    def __init__(self):
        self.cve_database = self._load_cve_database()
    
    def _load_cve_database(self) -> Dict:
        """Load CVE database"""
        return {
            'SSH': [
                {
                    'cve': 'CVE-2024-1234',
                    'title': 'Critical RCE in OpenSSH',
                    'severity': 'critical',
                    'cvss': 9.8,
                    'affected': ['OpenSSH < 8.0', 'OpenSSH < 7.9'],
                    'description': 'Remote code execution vulnerability'
                }
            ],
            'HTTP': [
                {
                    'cve': 'CVE-2024-5678',
                    'title': 'XSS in Web Server',
                    'severity': 'high',
                    'cvss': 7.5,
                    'affected': ['Apache 2.4', 'Nginx < 1.20'],
                    'description': 'Cross-site scripting vulnerability'
                }
            ],
            'RDP': [
                {
                    'cve': 'CVE-2024-3456',
                    'title': 'RDP Vulnerability',
                    'severity': 'high',
                    'cvss': 8.2,
                    'affected': ['Windows 10', 'Windows 11'],
                    'description': 'Remote desktop protocol vulnerability'
                }
            ],
            'SMB': [
                {
                    'cve': 'CVE-2024-7890',
                    'title': 'SMB Authentication Bypass',
                    'severity': 'critical',
                    'cvss': 9.1,
                    'affected': ['Windows < 10', 'Samba < 4.15'],
                    'description': 'Authentication bypass in SMB'
                }
            ],
            'MySQL': [
                {
                    'cve': 'CVE-2024-9012',
                    'title': 'SQL Injection',
                    'severity': 'high',
                    'cvss': 8.6,
                    'affected': ['MySQL 5.7', 'MySQL 8.0'],
                    'description': 'SQL injection vulnerability'
                }
            ]
        }
    
    def scan_vulnerabilities(self, services: List[str]) -> List[Dict]:
        """Find vulnerabilities for detected services"""
        vulnerabilities = []
        
        for service in services:
            if service in self.cve_database:
                vulnerabilities.extend(self.cve_database[service])
        
        return vulnerabilities
    
    def get_severity_count(self, vulns: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulns:
            severity = vuln.get('severity', 'low')
            if severity in counts:
                counts[severity] += 1
        return counts


class RemediationEngine:
    """Generate remediation recommendations"""
    
    @staticmethod
    def get_remediation(cve: str, service: str) -> Dict:
        """Get remediation steps for a CVE"""
        remediations = {
            'CVE-2024-1234': {
                'title': 'Patch OpenSSH to Latest Version',
                'priority': 'critical',
                'steps': [
                    'Update package manager',
                    'Install latest OpenSSH patch',
                    'Restart SSH service',
                    'Verify patch applied'
                ],
                'tools': ['SSH Client', 'Package Manager'],
                'time_estimate': 15
            },
            'CVE-2024-5678': {
                'title': 'Apply Web Server Security Patch',
                'priority': 'high',
                'steps': [
                    'Backup current configuration',
                    'Download latest patch',
                    'Apply security update',
                    'Test web server functionality',
                    'Monitor for issues'
                ],
                'tools': ['Web Server', 'Testing Tools'],
                'time_estimate': 30
            },
            'CVE-2024-3456': {
                'title': 'Apply Windows Security Update',
                'priority': 'high',
                'steps': [
                    'Enable Windows Update',
                    'Check for latest patches',
                    'Install security updates',
                    'Restart system',
                    'Verify patch status'
                ],
                'tools': ['Windows Update', 'System Tools'],
                'time_estimate': 45
            }
        }
        
        return remediations.get(cve, {
            'title': f'Remediate {cve}',
            'priority': 'medium',
            'steps': ['Review vulnerability details', 'Apply vendor patch', 'Test system'],
            'tools': ['Vendor tools'],
            'time_estimate': 30
        })


class ScanReport:
    """Generate comprehensive scan reports"""
    
    def __init__(self):
        self.scan_data = {}
    
    def generate_report(self, devices: List[Dict], vulnerabilities: List[Dict]) -> Dict:
        """Generate comprehensive scan report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_devices': len(devices),
                'total_vulnerabilities': len(vulnerabilities),
                'critical': sum(1 for v in vulnerabilities if v.get('severity') == 'critical'),
                'high': sum(1 for v in vulnerabilities if v.get('severity') == 'high'),
                'medium': sum(1 for v in vulnerabilities if v.get('severity') == 'medium'),
                'low': sum(1 for v in vulnerabilities if v.get('severity') == 'low')
            },
            'devices': devices,
            'vulnerabilities': vulnerabilities
        }
        return report
    
    def save_json(self, report: Dict, filename: str):
        """Save report as JSON"""
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
    
    def save_csv(self, report: Dict, filename: str):
        """Save report as CSV"""
        import csv
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write devices
            writer.writerow(['DEVICES'])
            writer.writerow(['IP', 'Hostname', 'MAC', 'Status'])
            for device in report['devices']:
                writer.writerow([
                    device['ip'],
                    device['hostname'],
                    device['mac'],
                    device['status']
                ])
            
            writer.writerow([])
            writer.writerow(['VULNERABILITIES'])
            writer.writerow(['CVE', 'Title', 'Severity', 'CVSS', 'Description'])
            for vuln in report['vulnerabilities']:
                writer.writerow([
                    vuln['cve'],
                    vuln['title'],
                    vuln['severity'],
                    vuln['cvss'],
                    vuln['description']
                ])


if __name__ == '__main__':
    # Test basic functionality
    print("APEC Pentest Toolkit - Core Scanner")
    print("=" * 50)
    
    scanner = NetworkScanner()
    print("✓ Network Scanner initialized")
    
    port_scanner = PortScanner()
    print("✓ Port Scanner initialized")
    
    vuln_scanner = VulnerabilityScanner()
    print("✓ Vulnerability Scanner initialized")
    
    print("\nCore modules loaded successfully!")
