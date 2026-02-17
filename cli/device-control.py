#!/usr/bin/env python3
"""
APEC Pentest Toolkit - Device Control CLI
Remote device management and command execution
"""

import sys
import os
import argparse
import json
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.device_control import (
    WindowsDeviceController, LinuxDeviceController,
    IoTDeviceController, NetworkDeviceController,
    DeviceControlManager
)


class DeviceControlCLI:
    """Command-line interface for device control"""
    
    def __init__(self):
        self.manager = DeviceControlManager()
    
    def print_banner(self):
        """Print tool banner"""
        banner = """
╔═══════════════════════════════════════════════════════════╗
║        APEC Pentest Facilitator - Device Control         ║
║     Remote Device Management and Command Execution       ║
╚═══════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def connect_windows(self, ip: str, username: str = None, password: str = None) -> bool:
        """Connect to Windows device"""
        print(f"\n[*] Connecting to Windows device {ip}...")
        
        controller = WindowsDeviceController(ip, username, password)
        if controller.connect():
            device_id = f"windows_{ip}"
            self.manager.add_device(device_id, controller)
            print(f"[✓] Connected to {ip}")
            return True
        else:
            print(f"[!] Failed to connect to {ip}")
            return False
    
    def connect_linux(self, ip: str, username: str = 'root', 
                     password: str = None, key_file: str = None) -> bool:
        """Connect to Linux device"""
        print(f"\n[*] Connecting to Linux device {ip}...")
        
        controller = LinuxDeviceController(ip, username=username, 
                                          password=password, key_file=key_file)
        if controller.connect():
            device_id = f"linux_{ip}"
            self.manager.add_device(device_id, controller)
            print(f"[✓] Connected to {ip}")
            return True
        else:
            print(f"[!] Failed to connect to {ip}")
            return False
    
    def connect_iot(self, ip: str, port: int = 80, protocol: str = 'http') -> bool:
        """Connect to IoT device"""
        print(f"\n[*] Connecting to IoT device {ip}:{port}...")
        
        controller = IoTDeviceController(ip, port, protocol)
        if controller.connect():
            device_id = f"iot_{ip}"
            self.manager.add_device(device_id, controller)
            print(f"[✓] Connected to {ip}")
            return True
        else:
            print(f"[!] Failed to connect to {ip}")
            return False
    
    def execute_command(self, device_type: str, ip: str, command: str, **kwargs) -> dict:
        """Execute command on device"""
        print(f"\n[*] Executing command on {device_type} device {ip}...")
        print(f"    Command: {command}")
        
        # Connect to device
        if device_type == 'windows':
            self.connect_windows(ip, kwargs.get('username'), kwargs.get('password'))
        elif device_type == 'linux':
            self.connect_linux(ip, kwargs.get('username', 'root'), 
                             kwargs.get('password'), kwargs.get('key_file'))
        elif device_type == 'iot':
            self.connect_iot(ip, kwargs.get('port', 80), kwargs.get('protocol', 'http'))
        
        # Execute command
        device_id = f"{device_type}_{ip}"
        result = self.manager.execute_on_device(device_id, command)
        
        if result.get('success'):
            print(f"\n[✓] Command executed successfully")
            if 'output' in result:
                print(f"\nOutput:\n{result['output']}")
        else:
            print(f"\n[!] Command failed: {result.get('error')}")
        
        return result
    
    def get_device_info(self, device_type: str, ip: str, **kwargs) -> dict:
        """Get device information"""
        print(f"\n[*] Getting information from {device_type} device {ip}...")
        
        # Connect to device
        if device_type == 'windows':
            self.connect_windows(ip, kwargs.get('username'), kwargs.get('password'))
        elif device_type == 'linux':
            self.connect_linux(ip, kwargs.get('username', 'root'), 
                             kwargs.get('password'), kwargs.get('key_file'))
        elif device_type == 'iot':
            self.connect_iot(ip, kwargs.get('port', 80), kwargs.get('protocol', 'http'))
        
        # Get info
        device_id = f"{device_type}_{ip}"
        info = self.manager.get_device_info(device_id)
        
        print(f"\n[+] Device Information:")
        for key, value in info.items():
            print(f"    {key}: {value}")
        
        return info
    
    def shutdown_device(self, device_type: str, ip: str, delay: int = 0, 
                       force: bool = False, **kwargs) -> bool:
        """Shutdown device"""
        print(f"\n[*] Shutting down {device_type} device {ip}...")
        
        # Connect to device
        if device_type == 'windows':
            controller = WindowsDeviceController(ip, kwargs.get('username'), 
                                               kwargs.get('password'))
        elif device_type == 'linux':
            controller = LinuxDeviceController(ip, username=kwargs.get('username', 'root'),
                                             password=kwargs.get('password'),
                                             key_file=kwargs.get('key_file'))
        else:
            print("[!] Shutdown not supported for this device type")
            return False
        
        if controller.connect():
            if controller.shutdown(delay, force):
                print(f"[✓] Shutdown command sent to {ip}")
                return True
            else:
                print(f"[!] Failed to shutdown {ip}")
                return False
        else:
            print(f"[!] Failed to connect to {ip}")
            return False
    
    def restart_device(self, device_type: str, ip: str, delay: int = 0, 
                      force: bool = False, **kwargs) -> bool:
        """Restart device"""
        print(f"\n[*] Restarting {device_type} device {ip}...")
        
        # Connect to device
        if device_type == 'windows':
            controller = WindowsDeviceController(ip, kwargs.get('username'),
                                               kwargs.get('password'))
        elif device_type == 'linux':
            controller = LinuxDeviceController(ip, username=kwargs.get('username', 'root'),
                                             password=kwargs.get('password'),
                                             key_file=kwargs.get('key_file'))
        else:
            print("[!] Restart not supported for this device type")
            return False
        
        if controller.connect():
            if controller.restart(delay, force):
                print(f"[✓] Restart command sent to {ip}")
                return True
            else:
                print(f"[!] Failed to restart {ip}")
                return False
        else:
            print(f"[!] Failed to connect to {ip}")
            return False
    
    def list_processes(self, device_type: str, ip: str, **kwargs) -> list:
        """List running processes"""
        print(f"\n[*] Getting processes from {device_type} device {ip}...")
        
        # Connect to device
        if device_type == 'windows':
            controller = WindowsDeviceController(ip, kwargs.get('username'),
                                               kwargs.get('password'))
        elif device_type == 'linux':
            controller = LinuxDeviceController(ip, username=kwargs.get('username', 'root'),
                                             password=kwargs.get('password'),
                                             key_file=kwargs.get('key_file'))
        else:
            print("[!] Process listing not supported for this device type")
            return []
        
        if controller.connect():
            processes = controller.get_running_processes()
            print(f"\n[+] Running Processes ({len(processes)}):")
            for proc in processes[:10]:  # Show first 10
                print(f"    {proc}")
            return processes
        else:
            print(f"[!] Failed to connect to {ip}")
            return []
    
    def list_services(self, device_type: str, ip: str, **kwargs) -> list:
        """List services"""
        print(f"\n[*] Getting services from {device_type} device {ip}...")
        
        # Connect to device
        if device_type == 'windows':
            controller = WindowsDeviceController(ip, kwargs.get('username'),
                                               kwargs.get('password'))
        elif device_type == 'linux':
            controller = LinuxDeviceController(ip, username=kwargs.get('username', 'root'),
                                             password=kwargs.get('password'),
                                             key_file=kwargs.get('key_file'))
        else:
            print("[!] Service listing not supported for this device type")
            return []
        
        if controller.connect():
            services = controller.get_services()
            print(f"\n[+] Services ({len(services)}):")
            for svc in services[:10]:  # Show first 10
                print(f"    {svc}")
            return services
        else:
            print(f"[!] Failed to connect to {ip}")
            return []


def main():
    parser = argparse.ArgumentParser(
        description='APEC Pentest Facilitator - Device Control',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python device-control.py execute windows 192.168.1.100 "ipconfig" -u admin -p password
  python device-control.py execute linux 192.168.1.50 "whoami" -u root -p password
  python device-control.py info windows 192.168.1.100 -u admin -p password
  python device-control.py shutdown windows 192.168.1.100 -u admin -p password
  python device-control.py restart linux 192.168.1.50 -u root -p password
  python device-control.py processes windows 192.168.1.100 -u admin -p password
  python device-control.py services linux 192.168.1.50 -u root -p password
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Execute command
    execute = subparsers.add_parser('execute', help='Execute command on device')
    execute.add_argument('device_type', choices=['windows', 'linux', 'iot'], 
                        help='Device type')
    execute.add_argument('ip', help='Device IP address')
    execute.add_argument('command', help='Command to execute')
    execute.add_argument('-u', '--username', help='Username')
    execute.add_argument('-p', '--password', help='Password')
    execute.add_argument('-k', '--key-file', help='SSH key file (Linux only)')
    
    # Get info
    info = subparsers.add_parser('info', help='Get device information')
    info.add_argument('device_type', choices=['windows', 'linux', 'iot'],
                     help='Device type')
    info.add_argument('ip', help='Device IP address')
    info.add_argument('-u', '--username', help='Username')
    info.add_argument('-p', '--password', help='Password')
    info.add_argument('-k', '--key-file', help='SSH key file (Linux only)')
    
    # Shutdown
    shutdown = subparsers.add_parser('shutdown', help='Shutdown device')
    shutdown.add_argument('device_type', choices=['windows', 'linux'],
                         help='Device type')
    shutdown.add_argument('ip', help='Device IP address')
    shutdown.add_argument('-d', '--delay', type=int, default=0, help='Delay in seconds')
    shutdown.add_argument('-f', '--force', action='store_true', help='Force shutdown')
    shutdown.add_argument('-u', '--username', help='Username')
    shutdown.add_argument('-p', '--password', help='Password')
    shutdown.add_argument('-k', '--key-file', help='SSH key file (Linux only)')
    
    # Restart
    restart = subparsers.add_parser('restart', help='Restart device')
    restart.add_argument('device_type', choices=['windows', 'linux'],
                        help='Device type')
    restart.add_argument('ip', help='Device IP address')
    restart.add_argument('-d', '--delay', type=int, default=0, help='Delay in seconds')
    restart.add_argument('-f', '--force', action='store_true', help='Force restart')
    restart.add_argument('-u', '--username', help='Username')
    restart.add_argument('-p', '--password', help='Password')
    restart.add_argument('-k', '--key-file', help='SSH key file (Linux only)')
    
    # List processes
    processes = subparsers.add_parser('processes', help='List running processes')
    processes.add_argument('device_type', choices=['windows', 'linux'],
                          help='Device type')
    processes.add_argument('ip', help='Device IP address')
    processes.add_argument('-u', '--username', help='Username')
    processes.add_argument('-p', '--password', help='Password')
    processes.add_argument('-k', '--key-file', help='SSH key file (Linux only)')
    
    # List services
    services = subparsers.add_parser('services', help='List services')
    services.add_argument('device_type', choices=['windows', 'linux'],
                         help='Device type')
    services.add_argument('ip', help='Device IP address')
    services.add_argument('-u', '--username', help='Username')
    services.add_argument('-p', '--password', help='Password')
    services.add_argument('-k', '--key-file', help='SSH key file (Linux only)')
    
    args = parser.parse_args()
    
    cli = DeviceControlCLI()
    cli.print_banner()
    
    if args.command == 'execute':
        cli.execute_command(args.device_type, args.ip, args.command,
                          username=args.username, password=args.password,
                          key_file=args.key_file)
    elif args.command == 'info':
        cli.get_device_info(args.device_type, args.ip,
                          username=args.username, password=args.password,
                          key_file=args.key_file)
    elif args.command == 'shutdown':
        cli.shutdown_device(args.device_type, args.ip, args.delay, args.force,
                          username=args.username, password=args.password,
                          key_file=args.key_file)
    elif args.command == 'restart':
        cli.restart_device(args.device_type, args.ip, args.delay, args.force,
                         username=args.username, password=args.password,
                         key_file=args.key_file)
    elif args.command == 'processes':
        cli.list_processes(args.device_type, args.ip,
                         username=args.username, password=args.password,
                         key_file=args.key_file)
    elif args.command == 'services':
        cli.list_services(args.device_type, args.ip,
                        username=args.username, password=args.password,
                        key_file=args.key_file)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
