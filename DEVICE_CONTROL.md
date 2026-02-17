# APEC Pentest Toolkit - Device Control Module

Complete remote device management and command execution for Windows, Linux, IoT, and network devices.

## Features

### Windows Device Control
- **Remote Command Execution**: Execute commands via WMI, PSExec, or RDP
- **System Information**: Get OS, hardware, processor, and memory details
- **Process Management**: List and manage running processes
- **Service Management**: Start, stop, restart services
- **System Control**: Shutdown and restart devices
- **File Operations**: Transfer files to/from devices

### Linux/Unix Device Control
- **SSH Remote Execution**: Execute commands over SSH
- **System Information**: Get OS, kernel, CPU, memory, uptime
- **Process Management**: List and manage running processes
- **Service Management**: Control systemd services
- **System Control**: Shutdown and restart devices
- **Key-based Authentication**: Support for SSH keys

### IoT Device Control
- **HTTP API Control**: Control devices via REST APIs
- **MQTT Support**: Communicate with MQTT-enabled devices
- **Device Discovery**: Find and identify IoT devices
- **Custom Commands**: Send device-specific commands

### Network Device Control
- **SNMP Management**: Query network devices
- **Configuration Access**: Read device configurations
- **Performance Monitoring**: Monitor device metrics

## Installation

### Prerequisites

```bash
# Windows
pip install paramiko pypsexec requests paho-mqtt

# Linux
pip3 install paramiko requests paho-mqtt
sudo apt-get install snmp snmp-mibs-downloader
```

### Quick Setup

```bash
# Install all dependencies
pip install -r requirements.txt
```

## Usage

### Command Line Interface

#### Execute Command on Windows Device

```bash
# Execute command with credentials
python device-control.py execute windows 192.168.1.100 "ipconfig" -u admin -p password

# Execute command without credentials (local network)
python device-control.py execute windows 192.168.1.100 "systeminfo"

# Execute PowerShell command
python device-control.py execute windows 192.168.1.100 "Get-Process" -u admin -p password
```

#### Execute Command on Linux Device

```bash
# SSH with password
python device-control.py execute linux 192.168.1.50 "whoami" -u root -p password

# SSH with key file
python device-control.py execute linux 192.168.1.50 "cat /etc/passwd" -u root -k ~/.ssh/id_rsa

# Execute as different user
python device-control.py execute linux 192.168.1.50 "sudo systemctl status nginx" -u ubuntu -p password
```

#### Get Device Information

```bash
# Windows device info
python device-control.py info windows 192.168.1.100 -u admin -p password

# Linux device info
python device-control.py info linux 192.168.1.50 -u root -p password

# IoT device info
python device-control.py info iot 192.168.1.200 --port 8080 --protocol http
```

#### Shutdown Device

```bash
# Shutdown Windows device
python device-control.py shutdown windows 192.168.1.100 -u admin -p password

# Shutdown with delay (60 seconds)
python device-control.py shutdown windows 192.168.1.100 -d 60 -u admin -p password

# Force shutdown
python device-control.py shutdown windows 192.168.1.100 -f -u admin -p password

# Shutdown Linux device
python device-control.py shutdown linux 192.168.1.50 -u root -p password
```

#### Restart Device

```bash
# Restart Windows device
python device-control.py restart windows 192.168.1.100 -u admin -p password

# Restart with delay
python device-control.py restart windows 192.168.1.100 -d 30 -u admin -p password

# Force restart
python device-control.py restart windows 192.168.1.100 -f -u admin -p password

# Restart Linux device
python device-control.py restart linux 192.168.1.50 -u root -p password
```

#### List Running Processes

```bash
# Windows processes
python device-control.py processes windows 192.168.1.100 -u admin -p password

# Linux processes
python device-control.py processes linux 192.168.1.50 -u root -p password
```

#### List Services

```bash
# Windows services
python device-control.py services windows 192.168.1.100 -u admin -p password

# Linux services
python device-control.py services linux 192.168.1.50 -u root -p password
```

### Python API

#### Basic Usage

```python
from core.device_control import WindowsDeviceController, LinuxDeviceController

# Windows device
windows = WindowsDeviceController('192.168.1.100', 'admin', 'password')
if windows.connect():
    result = windows.execute_command('ipconfig')
    print(result['output'])
    windows.disconnect()

# Linux device
linux = LinuxDeviceController('192.168.1.50', username='root', password='password')
if linux.connect():
    result = linux.execute_command('whoami')
    print(result['output'])
    linux.disconnect()
```

#### Device Management

```python
from core.device_control import DeviceControlManager

manager = DeviceControlManager()

# Add devices
windows = WindowsDeviceController('192.168.1.100', 'admin', 'password')
manager.add_device('win1', windows)

linux = LinuxDeviceController('192.168.1.50', username='root', password='password')
manager.add_device('linux1', linux)

# Execute on specific device
result = manager.execute_on_device('win1', 'ipconfig')

# Execute on all devices
results = manager.execute_on_all('systeminfo')

# Get device info
info = manager.get_device_info('linux1')
```

#### Advanced Operations

```python
# Get system information
info = windows.get_system_info()
print(f"OS: {info['os']}")
print(f"Hostname: {info['hostname']}")
print(f"Memory: {info['total_memory']} GB")

# List processes
processes = windows.get_running_processes()
for proc in processes:
    print(f"{proc['pid']}: {proc['name']}")

# List services
services = windows.get_services()
for svc in services:
    print(f"{svc['name']}: {svc['state']}")

# Control service
windows.control_service('sshd', 'start')
windows.control_service('sshd', 'stop')
windows.control_service('sshd', 'restart')

# Shutdown device
windows.shutdown(delay=60, force=False)

# Restart device
linux.restart(delay=30, force=False)
```

## Examples

### Network-Wide Command Execution

```python
from core.scanner import NetworkScanner
from core.device_control import LinuxDeviceController, DeviceControlManager

# Scan network
scanner = NetworkScanner()
devices = scanner.scan_network('192.168.1.0/24')

# Connect to all Linux devices
manager = DeviceControlManager()
for device in devices:
    linux = LinuxDeviceController(device['ip'], username='root', password='password')
    manager.add_device(device['ip'], linux)

# Execute command on all
results = manager.execute_on_all('uptime')
for device_id, result in results.items():
    print(f"{device_id}: {result['output']}")
```

### Automated System Hardening

```python
from core.device_control import WindowsDeviceController

windows = WindowsDeviceController('192.168.1.100', 'admin', 'password')
if windows.connect():
    # Disable unnecessary services
    windows.control_service('RemoteRegistry', 'stop')
    windows.control_service('Telnet', 'stop')
    
    # Enable Windows Firewall
    windows.execute_command('netsh advfirewall set allprofiles state on')
    
    # Update system
    windows.execute_command('wuauclt.exe /detectnow')
    
    windows.disconnect()
```

### Vulnerability Remediation

```python
from core.device_control import LinuxDeviceController

linux = LinuxDeviceController('192.168.1.50', username='root', password='password')
if linux.connect():
    # Update system
    linux.execute_command('apt-get update && apt-get upgrade -y')
    
    # Install security updates
    linux.execute_command('apt-get install -y unattended-upgrades')
    
    # Configure firewall
    linux.execute_command('ufw enable')
    linux.execute_command('ufw default deny incoming')
    linux.execute_command('ufw default allow outgoing')
    
    linux.disconnect()
```

## Security Considerations

### Authentication
- **Credentials**: Store credentials securely, never hardcode in scripts
- **SSH Keys**: Prefer key-based authentication for Linux devices
- **Encryption**: Use encrypted channels (SSH, HTTPS) for communication
- **Credentials File**: Use environment variables or config files

### Authorization
- **Permissions**: Ensure user has necessary permissions for operations
- **Audit Logging**: Enable audit logging on all managed devices
- **Role-Based Access**: Implement role-based access control

### Network Security
- **Firewall Rules**: Configure firewall to allow management traffic
- **Network Segmentation**: Use separate management network if possible
- **VPN/Bastion**: Use VPN or bastion host for remote access
- **Rate Limiting**: Implement rate limiting for API endpoints

### Device Hardening
- **Disable Unnecessary Services**: Turn off unused services
- **Strong Passwords**: Use strong, unique passwords
- **Regular Updates**: Keep systems patched and updated
- **Monitoring**: Monitor for unauthorized access attempts

## Troubleshooting

### Connection Failed

**Windows Device**
```bash
# Check if device is reachable
ping 192.168.1.100

# Check if SMB port is open
telnet 192.168.1.100 445

# Verify credentials
net use \\192.168.1.100 /user:admin password
```

**Linux Device**
```bash
# Check SSH connectivity
ssh -v root@192.168.1.50

# Check SSH port
telnet 192.168.1.50 22

# Verify key permissions
chmod 600 ~/.ssh/id_rsa
```

### Command Execution Failed

**Windows**
```bash
# Check WMI service
sc query winmgmt

# Restart WMI service
net stop winmgmt
net start winmgmt
```

**Linux**
```bash
# Check SSH service
systemctl status ssh

# Restart SSH service
sudo systemctl restart ssh
```

### Authentication Issues

**Windows**
- Verify user is in Administrators group
- Check if account is locked
- Verify password is correct

**Linux**
- Check if user has sudo privileges
- Verify SSH key permissions (600)
- Check if SSH key is added to authorized_keys

## API Reference

### WindowsDeviceController

```python
class WindowsDeviceController:
    def connect() -> bool
    def disconnect() -> bool
    def execute_command(command: str) -> Dict
    def get_system_info() -> Dict
    def shutdown(delay: int, force: bool) -> bool
    def restart(delay: int, force: bool) -> bool
    def get_running_processes() -> List[Dict]
    def get_services() -> List[Dict]
    def control_service(service_name: str, action: str) -> bool
```

### LinuxDeviceController

```python
class LinuxDeviceController:
    def connect() -> bool
    def disconnect() -> bool
    def execute_command(command: str) -> Dict
    def get_system_info() -> Dict
    def shutdown(delay: int, force: bool) -> bool
    def restart(delay: int, force: bool) -> bool
    def get_running_processes() -> List[Dict]
    def get_services() -> List[Dict]
    def control_service(service_name: str, action: str) -> bool
```

### IoTDeviceController

```python
class IoTDeviceController:
    def connect() -> bool
    def execute_command(command: str) -> Dict
    def get_system_info() -> Dict
```

### DeviceControlManager

```python
class DeviceControlManager:
    def add_device(device_id: str, controller: DeviceController) -> bool
    def remove_device(device_id: str) -> bool
    def execute_on_device(device_id: str, command: str) -> Dict
    def get_device_info(device_id: str) -> Dict
    def execute_on_all(command: str) -> Dict
```

## Support

For issues or questions, refer to the main README.md or contact your system administrator.

---

**Version**: 1.0.0  
**Status**: Production Ready
