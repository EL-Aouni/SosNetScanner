#!/usr/bin/env python3
"""
APEC Pentest Toolkit - Device Control Module
Remote device management and command execution
"""

import subprocess
import socket
import json
import sys
import os
from typing import Dict, List, Optional, Tuple
from datetime import datetime

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

try:
    import wmi
    WMI_AVAILABLE = True
except ImportError:
    WMI_AVAILABLE = False

try:
    from pypsexec.client import Client
    PSEXEC_AVAILABLE = True
except ImportError:
    PSEXEC_AVAILABLE = False


class DeviceController:
    """Base class for device control"""
    
    def __init__(self, ip: str, port: int = None):
        self.ip = ip
        self.port = port
        self.connected = False
        self.device_info = {}
    
    def connect(self) -> bool:
        """Connect to device"""
        raise NotImplementedError
    
    def disconnect(self) -> bool:
        """Disconnect from device"""
        raise NotImplementedError
    
    def execute_command(self, command: str) -> Dict:
        """Execute command on device"""
        raise NotImplementedError
    
    def get_system_info(self) -> Dict:
        """Get system information"""
        raise NotImplementedError
    
    def shutdown(self, delay: int = 0, force: bool = False) -> bool:
        """Shutdown device"""
        raise NotImplementedError
    
    def restart(self, delay: int = 0, force: bool = False) -> bool:
        """Restart device"""
        raise NotImplementedError


class WindowsDeviceController(DeviceController):
    """Control Windows devices via WMI, RDP, or PSExec"""
    
    def __init__(self, ip: str, username: str = None, password: str = None):
        super().__init__(ip)
        self.username = username
        self.password = password
        self.wmi_connection = None
        self.method = 'wmi'  # wmi, psexec, or rdp
    
    def connect(self) -> bool:
        """Connect to Windows device"""
        if not WMI_AVAILABLE:
            self.method = 'psexec' if PSEXEC_AVAILABLE else 'rdp'
        
        try:
            if self.method == 'wmi':
                # Try WMI connection
                if self.username and self.password:
                    self.wmi_connection = wmi.WMI(
                        computer=self.ip,
                        user=self.username,
                        password=self.password
                    )
                else:
                    self.wmi_connection = wmi.WMI(computer=self.ip)
                
                self.connected = True
                return True
            else:
                # Try PSExec or RDP
                self.connected = self.test_connection()
                return self.connected
        except Exception as e:
            print(f"[!] Failed to connect to {self.ip}: {e}")
            return False
    
    def disconnect(self) -> bool:
        """Disconnect from Windows device"""
        self.wmi_connection = None
        self.connected = False
        return True
    
    def test_connection(self) -> bool:
        """Test connection to device"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.ip, 445))  # SMB port
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def execute_command(self, command: str) -> Dict:
        """Execute command on Windows device"""
        if not self.connected:
            return {'success': False, 'error': 'Not connected'}
        
        try:
            if self.method == 'wmi':
                # Execute via WMI
                process = self.wmi_connection.Win32_Process.Create(CommandLine=command)
                return {
                    'success': True,
                    'command': command,
                    'process_id': process[0],
                    'return_code': process[1]
                }
            else:
                # Execute via PSExec or direct command
                result = subprocess.run(
                    ['psexec.exe', f'\\\\{self.ip}', command],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                return {
                    'success': result.returncode == 0,
                    'command': command,
                    'output': result.stdout,
                    'error': result.stderr
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_system_info(self) -> Dict:
        """Get Windows system information"""
        if not self.connected:
            return {}
        
        try:
            info = {}
            
            # OS Information
            os_info = self.wmi_connection.Win32_OperatingSystem()[0]
            info['os'] = os_info.Caption
            info['version'] = os_info.Version
            info['build'] = os_info.BuildNumber
            info['install_date'] = os_info.InstallDate
            
            # Computer Info
            comp_info = self.wmi_connection.Win32_ComputerSystem()[0]
            info['hostname'] = comp_info.Name
            info['manufacturer'] = comp_info.Manufacturer
            info['model'] = comp_info.Model
            info['total_memory'] = int(comp_info.TotalPhysicalMemory) / (1024**3)  # GB
            
            # Processor Info
            proc_info = self.wmi_connection.Win32_Processor()[0]
            info['processor'] = proc_info.Name
            info['cores'] = proc_info.NumberOfCores
            
            return info
        except Exception as e:
            return {'error': str(e)}
    
    def shutdown(self, delay: int = 0, force: bool = False) -> bool:
        """Shutdown Windows device"""
        try:
            flags = 1 if force else 0  # 1 = force, 0 = normal
            self.wmi_connection.Win32_OperatingSystem()[0].Shutdown(Flags=flags)
            return True
        except Exception as e:
            print(f"[!] Failed to shutdown: {e}")
            return False
    
    def restart(self, delay: int = 0, force: bool = False) -> bool:
        """Restart Windows device"""
        try:
            flags = 2 if force else 0  # 2 = reboot, 0 = normal
            self.wmi_connection.Win32_OperatingSystem()[0].Reboot(Flags=flags)
            return True
        except Exception as e:
            print(f"[!] Failed to restart: {e}")
            return False
    
    def get_running_processes(self) -> List[Dict]:
        """Get list of running processes"""
        try:
            processes = []
            for proc in self.wmi_connection.Win32_Process():
                processes.append({
                    'pid': proc.ProcessId,
                    'name': proc.Name,
                    'command_line': proc.CommandLine
                })
            return processes
        except Exception:
            return []
    
    def get_services(self) -> List[Dict]:
        """Get list of services"""
        try:
            services = []
            for svc in self.wmi_connection.Win32_Service():
                services.append({
                    'name': svc.Name,
                    'display_name': svc.DisplayName,
                    'state': svc.State,
                    'start_mode': svc.StartMode
                })
            return services
        except Exception:
            return []
    
    def control_service(self, service_name: str, action: str) -> bool:
        """Control a service (start, stop, restart)"""
        try:
            service = self.wmi_connection.Win32_Service(Name=service_name)[0]
            
            if action.lower() == 'start':
                service.StartService()
            elif action.lower() == 'stop':
                service.StopService()
            elif action.lower() == 'restart':
                service.StopService()
                service.StartService()
            
            return True
        except Exception as e:
            print(f"[!] Failed to control service: {e}")
            return False


class LinuxDeviceController(DeviceController):
    """Control Linux/Unix devices via SSH"""
    
    def __init__(self, ip: str, port: int = 22, username: str = 'root', 
                 password: str = None, key_file: str = None):
        super().__init__(ip, port)
        self.username = username
        self.password = password
        self.key_file = key_file
        self.ssh_client = None
    
    def connect(self) -> bool:
        """Connect to Linux device via SSH"""
        if not PARAMIKO_AVAILABLE:
            print("[!] Paramiko not installed. Install with: pip install paramiko")
            return False
        
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if self.key_file:
                self.ssh_client.connect(
                    self.ip,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key_file,
                    timeout=5
                )
            else:
                self.ssh_client.connect(
                    self.ip,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=5
                )
            
            self.connected = True
            return True
        except Exception as e:
            print(f"[!] Failed to connect to {self.ip}: {e}")
            return False
    
    def disconnect(self) -> bool:
        """Disconnect from Linux device"""
        if self.ssh_client:
            self.ssh_client.close()
        self.connected = False
        return True
    
    def execute_command(self, command: str) -> Dict:
        """Execute command on Linux device"""
        if not self.connected:
            return {'success': False, 'error': 'Not connected'}
        
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            return {
                'success': True,
                'command': command,
                'output': output,
                'error': error,
                'return_code': stdout.channel.recv_exit_status()
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_system_info(self) -> Dict:
        """Get Linux system information"""
        if not self.connected:
            return {}
        
        try:
            info = {}
            
            # Hostname
            _, stdout, _ = self.ssh_client.exec_command('hostname')
            info['hostname'] = stdout.read().decode().strip()
            
            # OS Info
            _, stdout, _ = self.ssh_client.exec_command('cat /etc/os-release')
            os_info = stdout.read().decode()
            info['os_info'] = os_info
            
            # Kernel
            _, stdout, _ = self.ssh_client.exec_command('uname -r')
            info['kernel'] = stdout.read().decode().strip()
            
            # CPU Info
            _, stdout, _ = self.ssh_client.exec_command('nproc')
            info['cpu_cores'] = int(stdout.read().decode().strip())
            
            # Memory
            _, stdout, _ = self.ssh_client.exec_command('free -h | grep Mem')
            info['memory'] = stdout.read().decode().strip()
            
            # Uptime
            _, stdout, _ = self.ssh_client.exec_command('uptime')
            info['uptime'] = stdout.read().decode().strip()
            
            return info
        except Exception as e:
            return {'error': str(e)}
    
    def shutdown(self, delay: int = 0, force: bool = False) -> bool:
        """Shutdown Linux device"""
        try:
            if force:
                cmd = f'shutdown -h +{delay} -f'
            else:
                cmd = f'shutdown -h +{delay}'
            
            result = self.execute_command(cmd)
            return result['success']
        except Exception as e:
            print(f"[!] Failed to shutdown: {e}")
            return False
    
    def restart(self, delay: int = 0, force: bool = False) -> bool:
        """Restart Linux device"""
        try:
            if force:
                cmd = f'shutdown -r +{delay} -f'
            else:
                cmd = f'shutdown -r +{delay}'
            
            result = self.execute_command(cmd)
            return result['success']
        except Exception as e:
            print(f"[!] Failed to restart: {e}")
            return False
    
    def get_running_processes(self) -> List[Dict]:
        """Get list of running processes"""
        try:
            result = self.execute_command('ps aux')
            processes = []
            for line in result['output'].split('\n')[1:]:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 11:
                        processes.append({
                            'user': parts[0],
                            'pid': parts[1],
                            'cpu': parts[2],
                            'memory': parts[3],
                            'command': ' '.join(parts[10:])
                        })
            return processes
        except Exception:
            return []
    
    def get_services(self) -> List[Dict]:
        """Get list of services"""
        try:
            result = self.execute_command('systemctl list-units --type=service')
            services = []
            for line in result['output'].split('\n')[1:]:
                if line.strip() and '.service' in line:
                    parts = line.split()
                    services.append({
                        'name': parts[0],
                        'state': parts[3] if len(parts) > 3 else 'unknown'
                    })
            return services
        except Exception:
            return []
    
    def control_service(self, service_name: str, action: str) -> bool:
        """Control a service (start, stop, restart)"""
        try:
            cmd = f'systemctl {action} {service_name}'
            result = self.execute_command(cmd)
            return result['success']
        except Exception as e:
            print(f"[!] Failed to control service: {e}")
            return False


class IoTDeviceController(DeviceController):
    """Control IoT devices via HTTP/MQTT"""
    
    def __init__(self, ip: str, port: int = 80, protocol: str = 'http'):
        super().__init__(ip, port)
        self.protocol = protocol
        self.base_url = f'{protocol}://{ip}:{port}'
    
    def connect(self) -> bool:
        """Test connection to IoT device"""
        try:
            try:
                import requests
            except ImportError:
                print("[!] Requests not installed. Install with: pip install requests")
                return False
            
            response = requests.get(f'{self.base_url}/', timeout=2)
            self.connected = response.status_code < 500
            return self.connected
        except Exception:
            return False
    
    def execute_command(self, command: str) -> Dict:
        """Execute command on IoT device"""
        try:
            import requests
            response = requests.get(
                f'{self.base_url}/api/command',
                params={'cmd': command},
                timeout=5
            )
            return {
                'success': response.status_code == 200,
                'response': response.text
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_system_info(self) -> Dict:
        """Get IoT device information"""
        try:
            import requests
            response = requests.get(f'{self.base_url}/api/info', timeout=5)
            if response.status_code == 200:
                return response.json()
            return {}
        except Exception:
            return {}


class NetworkDeviceController(DeviceController):
    """Control network devices (routers, switches) via SNMP or SSH"""
    
    def __init__(self, ip: str, community: str = 'public', protocol: str = 'snmp'):
        super().__init__(ip)
        self.community = community
        self.protocol = protocol
    
    def connect(self) -> bool:
        """Connect to network device"""
        try:
            if self.protocol == 'snmp':
                # Test SNMP connectivity
                import subprocess
                result = subprocess.run(
                    ['snmpget', '-v2c', '-c', self.community, self.ip, '1.3.6.1.2.1.1.1.0'],
                    capture_output=True,
                    timeout=2
                )
                self.connected = result.returncode == 0
            else:
                # Test SSH connectivity
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.ip, 22))
                sock.close()
                self.connected = result == 0
            
            return self.connected
        except Exception:
            return False
    
    def get_system_info(self) -> Dict:
        """Get network device information"""
        try:
            import subprocess
            result = subprocess.run(
                ['snmpget', '-v2c', '-c', self.community, self.ip, 
                 '1.3.6.1.2.1.1.1.0', '1.3.6.1.2.1.1.3.0'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return {'info': result.stdout}
        except Exception:
            return {}


class DeviceControlManager:
    """Manage multiple device controllers"""
    
    def __init__(self):
        self.devices = {}
    
    def add_device(self, device_id: str, controller: DeviceController) -> bool:
        """Add device controller"""
        self.devices[device_id] = controller
        return controller.connect()
    
    def remove_device(self, device_id: str) -> bool:
        """Remove device controller"""
        if device_id in self.devices:
            self.devices[device_id].disconnect()
            del self.devices[device_id]
            return True
        return False
    
    def execute_on_device(self, device_id: str, command: str) -> Dict:
        """Execute command on specific device"""
        if device_id not in self.devices:
            return {'success': False, 'error': 'Device not found'}
        
        return self.devices[device_id].execute_command(command)
    
    def get_device_info(self, device_id: str) -> Dict:
        """Get device information"""
        if device_id not in self.devices:
            return {}
        
        return self.devices[device_id].get_system_info()
    
    def execute_on_all(self, command: str) -> Dict:
        """Execute command on all connected devices"""
        results = {}
        for device_id, controller in self.devices.items():
            results[device_id] = controller.execute_command(command)
        return results


if __name__ == '__main__':
    print("APEC Pentest Toolkit - Device Control Module")
    print("=" * 50)
    print("✓ Windows Device Controller available")
    print("✓ Linux Device Controller available")
    print("✓ IoT Device Controller available")
    print("✓ Network Device Controller available")
    print("\nDevice control module loaded successfully!")
