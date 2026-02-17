#!/usr/bin/env python3
"""
APEC Pentest Toolkit - GUI Dashboard
Desktop application for visualization and management
"""

import sys
import os
import json
import threading
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.scanner import (
    NetworkScanner, PortScanner, OSDetection,
    VulnerabilityScanner, RemediationEngine, ScanReport
)

try:
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QTableWidget, QTableWidgetItem, QPushButton, QLineEdit,
        QLabel, QProgressBar, QComboBox, QSpinBox, QMessageBox, QFileDialog,
        QTextEdit, QDialog, QFormLayout, QListWidget, QListWidgetItem,
        QHeaderView, QStatusBar
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QColor, QFont, QIcon
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False
    print("PyQt6 not installed. Install with: pip install PyQt6")
    print("Falling back to CLI mode...")


class ScanWorker(QThread):
    """Worker thread for scanning operations"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, scan_type, target, **kwargs):
        super().__init__()
        self.scan_type = scan_type
        self.target = target
        self.kwargs = kwargs
    
    def run(self):
        try:
            scanner = NetworkScanner()
            port_scanner = PortScanner()
            vuln_scanner = VulnerabilityScanner()
            
            if self.scan_type == 'network':
                self.progress.emit(f"Scanning network {self.target}...")
                devices = scanner.scan_network(self.target)
                self.finished.emit({'type': 'network', 'data': devices})
            
            elif self.scan_type == 'ports':
                self.progress.emit(f"Scanning ports on {self.target}...")
                ports = port_scanner.scan_ports(self.target)
                self.finished.emit({'type': 'ports', 'data': ports})
            
            elif self.scan_type == 'full':
                self.progress.emit(f"Starting full scan on {self.target}...")
                devices = scanner.scan_network(self.target)
                
                all_vulns = []
                for device in devices:
                    self.progress.emit(f"Analyzing {device['ip']}...")
                    ports = port_scanner.scan_ports(device['ip'])
                    services = [p['service'] for p in ports]
                    vulns = vuln_scanner.scan_vulnerabilities(services)
                    all_vulns.extend(vulns)
                
                report = ScanReport().generate_report(devices, all_vulns)
                self.finished.emit({'type': 'full', 'data': report})
        
        except Exception as e:
            self.error.emit(str(e))


class Dashboard(QMainWindow):
    """Main dashboard GUI"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle('APEC Pentest Facilitator - Dashboard')
        self.setGeometry(100, 100, 1400, 900)
        
        self.scanner = NetworkScanner()
        self.port_scanner = PortScanner()
        self.vuln_scanner = VulnerabilityScanner()
        self.report_gen = ScanReport()
        
        self.scan_results = {}
        self.current_scan_thread = None
        
        self.init_ui()
    
    def init_ui(self):
        """Initialize user interface"""
        # Central widget
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        
        # Create tabs
        tabs = QTabWidget()
        
        tabs.addTab(self.create_scan_tab(), "Network Scan")
        tabs.addTab(self.create_analysis_tab(), "Device Analysis")
        tabs.addTab(self.create_vulnerabilities_tab(), "Vulnerabilities")
        tabs.addTab(self.create_remediation_tab(), "Remediation")
        tabs.addTab(self.create_reports_tab(), "Reports")
        
        layout.addWidget(tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready")
    
    def create_scan_tab(self):
        """Create network scan tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Input section
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Network Range (CIDR):"))
        self.cidr_input = QLineEdit("192.168.1.0/24")
        input_layout.addWidget(self.cidr_input)
        
        scan_btn = QPushButton("Start Scan")
        scan_btn.clicked.connect(self.start_network_scan)
        input_layout.addWidget(scan_btn)
        
        layout.addLayout(input_layout)
        
        # Progress bar
        self.scan_progress = QProgressBar()
        self.scan_progress.setVisible(False)
        layout.addWidget(self.scan_progress)
        
        # Results table
        self.scan_table = QTableWidget()
        self.scan_table.setColumnCount(4)
        self.scan_table.setHorizontalHeaderLabels(['IP Address', 'Hostname', 'MAC Address', 'Status'])
        self.scan_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.scan_table)
        
        # Status label
        self.scan_status = QLabel("No scan performed yet")
        layout.addWidget(self.scan_status)
        
        widget.setLayout(layout)
        return widget
    
    def create_analysis_tab(self):
        """Create device analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Input section
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target IP:"))
        self.analysis_ip = QLineEdit("192.168.1.1")
        input_layout.addWidget(self.analysis_ip)
        
        analyze_btn = QPushButton("Analyze Device")
        analyze_btn.clicked.connect(self.analyze_device)
        input_layout.addWidget(analyze_btn)
        
        layout.addLayout(input_layout)
        
        # Results section
        layout.addWidget(QLabel("Open Ports:"))
        self.ports_table = QTableWidget()
        self.ports_table.setColumnCount(2)
        self.ports_table.setHorizontalHeaderLabels(['Port', 'Service'])
        layout.addWidget(self.ports_table)
        
        layout.addWidget(QLabel("Vulnerabilities:"))
        self.analysis_vulns = QTextEdit()
        self.analysis_vulns.setReadOnly(True)
        layout.addWidget(self.analysis_vulns)
        
        widget.setLayout(layout)
        return widget
    
    def create_vulnerabilities_tab(self):
        """Create vulnerabilities tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Filter section
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by Severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(['All', 'Critical', 'High', 'Medium', 'Low'])
        self.severity_filter.currentTextChanged.connect(self.update_vulnerabilities_table)
        filter_layout.addWidget(self.severity_filter)
        filter_layout.addStretch()
        
        layout.addLayout(filter_layout)
        
        # Vulnerabilities table
        self.vulns_table = QTableWidget()
        self.vulns_table.setColumnCount(5)
        self.vulns_table.setHorizontalHeaderLabels(['CVE ID', 'Title', 'Severity', 'CVSS', 'Description'])
        self.vulns_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.vulns_table)
        
        widget.setLayout(layout)
        return widget
    
    def create_remediation_tab(self):
        """Create remediation tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # CVE input
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("CVE ID:"))
        self.cve_input = QLineEdit("CVE-2024-1234")
        input_layout.addWidget(self.cve_input)
        
        get_btn = QPushButton("Get Remediation")
        get_btn.clicked.connect(self.show_remediation)
        input_layout.addWidget(get_btn)
        
        layout.addLayout(input_layout)
        
        # Remediation details
        self.remediation_text = QTextEdit()
        self.remediation_text.setReadOnly(True)
        layout.addWidget(self.remediation_text)
        
        widget.setLayout(layout)
        return widget
    
    def create_reports_tab(self):
        """Create reports tab"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Export buttons
        button_layout = QHBoxLayout()
        
        export_json_btn = QPushButton("Export as JSON")
        export_json_btn.clicked.connect(lambda: self.export_report('json'))
        button_layout.addWidget(export_json_btn)
        
        export_csv_btn = QPushButton("Export as CSV")
        export_csv_btn.clicked.connect(lambda: self.export_report('csv'))
        button_layout.addWidget(export_csv_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # Report preview
        layout.addWidget(QLabel("Report Preview:"))
        self.report_text = QTextEdit()
        self.report_text.setReadOnly(True)
        layout.addWidget(self.report_text)
        
        widget.setLayout(layout)
        return widget
    
    def start_network_scan(self):
        """Start network scan"""
        cidr = self.cidr_input.text()
        
        if not self.scanner.is_valid_cidr(cidr):
            QMessageBox.warning(self, "Invalid CIDR", f"Invalid CIDR notation: {cidr}")
            return
        
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        
        self.current_scan_thread = ScanWorker('network', cidr)
        self.current_scan_thread.progress.connect(self.update_status)
        self.current_scan_thread.finished.connect(self.on_scan_finished)
        self.current_scan_thread.error.connect(self.on_scan_error)
        self.current_scan_thread.start()
    
    def analyze_device(self):
        """Analyze single device"""
        ip = self.analysis_ip.text()
        
        self.current_scan_thread = ScanWorker('ports', ip)
        self.current_scan_thread.finished.connect(self.on_analysis_finished)
        self.current_scan_thread.error.connect(self.on_scan_error)
        self.current_scan_thread.start()
    
    def on_scan_finished(self, result):
        """Handle scan completion"""
        self.scan_results = result['data']
        
        if result['type'] == 'network':
            self.scan_table.setRowCount(0)
            for device in result['data']:
                row = self.scan_table.rowCount()
                self.scan_table.insertRow(row)
                self.scan_table.setItem(row, 0, QTableWidgetItem(device['ip']))
                self.scan_table.setItem(row, 1, QTableWidgetItem(device['hostname']))
                self.scan_table.setItem(row, 2, QTableWidgetItem(device['mac']))
                self.scan_table.setItem(row, 3, QTableWidgetItem(device['status']))
            
            self.scan_status.setText(f"Scan complete: {len(result['data'])} device(s) found")
        
        self.scan_progress.setVisible(False)
        self.statusBar().showMessage("Scan completed successfully")
    
    def on_analysis_finished(self, result):
        """Handle analysis completion"""
        self.ports_table.setRowCount(0)
        for port in result['data']:
            row = self.ports_table.rowCount()
            self.ports_table.insertRow(row)
            self.ports_table.setItem(row, 0, QTableWidgetItem(str(port['port'])))
            self.ports_table.setItem(row, 1, QTableWidgetItem(port['service']))
    
    def on_scan_error(self, error):
        """Handle scan error"""
        QMessageBox.critical(self, "Scan Error", f"Error during scan: {error}")
        self.statusBar().showMessage("Scan failed")
    
    def update_status(self, message):
        """Update status message"""
        self.statusBar().showMessage(message)
    
    def update_vulnerabilities_table(self):
        """Update vulnerabilities table based on filter"""
        severity = self.severity_filter.currentText().lower()
        
        vulns = self.vuln_scanner.vulnerabilities if hasattr(self.vuln_scanner, 'vulnerabilities') else []
        
        self.vulns_table.setRowCount(0)
        # Add sample vulnerabilities
        sample_vulns = [
            {'cve': 'CVE-2024-1234', 'title': 'Critical RCE', 'severity': 'critical', 'cvss': 9.8},
            {'cve': 'CVE-2024-5678', 'title': 'SQL Injection', 'severity': 'high', 'cvss': 8.6},
        ]
        
        for vuln in sample_vulns:
            if severity == 'all' or vuln['severity'] == severity:
                row = self.vulns_table.rowCount()
                self.vulns_table.insertRow(row)
                self.vulns_table.setItem(row, 0, QTableWidgetItem(vuln['cve']))
                self.vulns_table.setItem(row, 1, QTableWidgetItem(vuln['title']))
                self.vulns_table.setItem(row, 2, QTableWidgetItem(vuln['severity']))
                self.vulns_table.setItem(row, 3, QTableWidgetItem(str(vuln['cvss'])))
    
    def show_remediation(self):
        """Show remediation for CVE"""
        cve = self.cve_input.text()
        remediation = RemediationEngine.get_remediation(cve, '')
        
        text = f"CVE: {cve}\n"
        text += f"Title: {remediation['title']}\n"
        text += f"Priority: {remediation['priority']}\n"
        text += f"Time Estimate: {remediation['time_estimate']} minutes\n\n"
        text += "Steps:\n"
        for i, step in enumerate(remediation['steps'], 1):
            text += f"{i}. {step}\n"
        text += f"\nTools: {', '.join(remediation['tools'])}"
        
        self.remediation_text.setText(text)
    
    def export_report(self, format_type):
        """Export report"""
        if not self.scan_results:
            QMessageBox.warning(self, "No Data", "No scan results to export")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            f"Export as {format_type.upper()}",
            f"report.{format_type}",
            f"{format_type.upper()} Files (*.{format_type})"
        )
        
        if filename:
            try:
                if format_type == 'json':
                    self.report_gen.save_json(self.scan_results, filename)
                elif format_type == 'csv':
                    self.report_gen.save_csv(self.scan_results, filename)
                
                QMessageBox.information(self, "Success", f"Report exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export: {e}")


def main():
    if not PYQT_AVAILABLE:
        print("PyQt6 is required for GUI mode.")
        print("Install with: pip install PyQt6")
        sys.exit(1)
    
    app = QApplication(sys.argv)
    dashboard = Dashboard()
    dashboard.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
