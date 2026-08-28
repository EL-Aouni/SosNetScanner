#!/usr/bin/env python3
"""
SosNetScanner - Core Network Scanner
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
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkScanner:
    """Real network device discovery and scanning"""
    
    def __init__(self, timeout: int = 5, max_threads: int = 50):
        self.timeout = timeout
        self.max_threads = max_threads
        self.discovered_devices = []
        self.lock = threading.Lock()
        self.last_scan_method = None
    
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
    
    def arp_scan(self, cidr: str, callback=None) -> Optional[List[Dict]]:
        """
        Discover devices using ARP requests (scapy).
        Much more reliable than ICMP ping: works even when hosts/firewalls
        block ping, and it's how 'arp-scan'/most real scanners do it.
        Requires scapy + raw socket privileges (root/administrator).
        Returns None if scapy isn't available or the scan can't run
        (e.g. insufficient privileges), so the caller can fall back to ping.
        """
        if not SCAPY_AVAILABLE:
            return None

        try:
            conf.verb = 0  # silence scapy's own logging
            arp_request = ARP(pdst=cidr)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request

            answered, _ = srp(packet, timeout=self.timeout, retry=1)

            devices = []
            for _, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                hostname = self.get_hostname(ip)

                device = {
                    'ip': ip,
                    'hostname': hostname,
                    'mac': mac,
                    'status': 'online',
                    'timestamp': datetime.now().isoformat()
                }
                devices.append(device)
                if callback:
                    callback(device)

            with self.lock:
                self.discovered_devices = devices

            return devices
        except PermissionError:
            # Needs root/administrator for raw sockets - let caller fall back
            return None
        except Exception:
            # Any other scapy/OS-level failure - fall back to ping instead
            # of silently reporting zero devices with no explanation.
            return None

    def scan_network(self, cidr: str, callback=None) -> List[Dict]:
        """
        Scan network and discover devices.

        Tries ARP scanning first (fast, reliable, doesn't depend on ICMP
        being allowed). Falls back to threaded ICMP ping if ARP isn't
        available (no scapy, no root/admin privileges, or the CIDR isn't
        on a locally-attached subnet, e.g. scanning across routers/WAN).
        """
        if not self.is_valid_cidr(cidr):
            raise ValueError(f"Invalid CIDR: {cidr}")

        arp_result = self.arp_scan(cidr, callback=callback)
        if arp_result is not None:
            self.last_scan_method = 'arp'
            return arp_result

        self.last_scan_method = 'ping'
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
                sock.settimeout(self.timeout)
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

    # Default location of the real, external CVE database relative to this file
    DEFAULT_DB_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'data', 'cve_database.json'
    )

    def __init__(self, db_path: str = None):
        self.db_path = db_path or self.DEFAULT_DB_PATH
        self.cve_database = self._load_cve_database()

    def _load_cve_database(self) -> Dict:
        """
        Load the CVE database from data/cve_database.json (real, published
        CVEs, verified against NVD/vendor advisories). Falls back to a
        small built-in set only if the JSON file is missing or unreadable,
        so the tool still works but the person is warned it's degraded.
        """
        try:
            with open(self.db_path, 'r') as f:
                data = json.load(f)
            data.pop('_notes', None)
            return data
        except (FileNotFoundError, json.JSONDecodeError, OSError) as e:
            print(f"[!] Warning: could not load {self.db_path} ({e}). "
                  f"Falling back to a minimal built-in CVE set - "
                  f"results will be incomplete.")
            return {
                'SSH': [
                    {
                        'cve': 'CVE-2024-6387',
                        'title': 'regreSSHion - OpenSSH RCE',
                        'severity': 'high',
                        'cvss': 8.1,
                        'affected': ['OpenSSH 8.5p1 - 9.7p1'],
                        'description': 'Race condition RCE in sshd signal handler',
                        'is_cve': True
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
    """Generate remediation recommendations, sourced from cve_database.json"""

    def __init__(self, db_path: str = None):
        # Reuse VulnerabilityScanner's loader/database so remediation data
        # can never drift out of sync with the CVE entries it belongs to.
        self._vuln_scanner = VulnerabilityScanner(db_path=db_path)

    def get_remediation(self, cve: str, service: str = None) -> Dict:
        """Get remediation steps for a CVE from the loaded database"""
        # Search across all services for a matching CVE id (or check the
        # given service first, if provided, to avoid a full scan)
        services_to_check = (
            [service] + [s for s in self._vuln_scanner.cve_database if s != service]
            if service else list(self._vuln_scanner.cve_database)
        )

        for svc in services_to_check:
            for entry in self._vuln_scanner.cve_database.get(svc, []):
                if entry.get('cve') == cve and 'remediation' in entry:
                    return entry['remediation']

        # No match found in the database - generic fallback
        return {
            'title': f'Remediate {cve}',
            'priority': 'medium',
            'steps': [
                'Look up this CVE/finding ID against your vendor\'s advisory or NVD',
                'Apply the recommended vendor patch or configuration change',
                'Test the affected system after remediation'
            ],
            'tools': ['Vendor advisory', 'NVD (nvd.nist.gov)'],
            'time_estimate': 30
        }


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
    print("SosNetScanner - Core Scanner")
    print("=" * 50)
    
    scanner = NetworkScanner()
    print("✓ Network Scanner initialized")
    
    port_scanner = PortScanner()
    print("✓ Port Scanner initialized")
    
    vuln_scanner = VulnerabilityScanner()
    print("✓ Vulnerability Scanner initialized")
    
    print("\nCore modules loaded successfully!")
