import sys
import os
from pathlib import Path
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QLabel, QFileDialog, 
                           QTreeWidget, QTreeWidgetItem, QProgressBar, 
                           QTextEdit, QTabWidget, QSpinBox, QComboBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QColor, QPalette, QFont, QIcon
from scanner_core import SecurityScanner, Severity
from qt_material import apply_stylesheet
import threading
from datetime import datetime
from rich.console import Console
import io

class ScanWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(list)
    status_update = pyqtSignal(str)
    
    def __init__(self, directory, extensions):
        super().__init__()
        self.directory = directory
        self.extensions = extensions
        self.scanner = SecurityScanner()
        
    def run(self):
        try:
            issues = self.scanner.scan_directory(Path(self.directory), self.extensions)
            self.finished.emit(issues)
        except Exception as e:
            self.status_update.emit(f"Error: {str(e)}")

class SecurityScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security File Scanner")
        self.setMinimumSize(1200, 800)
        
        # Apply dark theme
        apply_stylesheet(self, theme='dark_teal.xml')
        
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Header
        header = QLabel("Security File Scanner")
        header.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        # Control panel
        control_panel = QHBoxLayout()
        
        # Directory selection
        self.dir_label = QLabel("No directory selected")
        select_dir_btn = QPushButton("Select Directory")
        select_dir_btn.clicked.connect(self.select_directory)
        control_panel.addWidget(select_dir_btn)
        control_panel.addWidget(self.dir_label)
        
        # Scan button
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        self.scan_btn.setEnabled(False)
        control_panel.addWidget(self.scan_btn)
        
        layout.addLayout(control_panel)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)
        
        # Results tabs
        self.tabs = QTabWidget()
        
        # Summary tab
        summary_widget = QWidget()
        summary_layout = QVBoxLayout(summary_widget)
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        summary_layout.addWidget(self.summary_text)
        self.tabs.addTab(summary_widget, "Summary")
        
        # Details tab
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        
        # Filters
        filters_layout = QHBoxLayout()
        
        # Severity filter
        severity_label = QLabel("Severity:")
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All"] + [s.value for s in Severity])
        self.severity_filter.currentTextChanged.connect(self.filter_results)
        filters_layout.addWidget(severity_label)
        filters_layout.addWidget(self.severity_filter)
        
        details_layout.addLayout(filters_layout)
        
        # Results tree
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["File", "Line", "Severity", "Issue"])
        self.results_tree.setColumnWidth(0, 300)
        self.results_tree.setColumnWidth(1, 100)
        self.results_tree.setColumnWidth(2, 100)
        self.results_tree.setColumnWidth(3, 400)
        details_layout.addWidget(self.results_tree)
        
        # Context viewer
        self.context_viewer = QTextEdit()
        self.context_viewer.setReadOnly(True)
        self.context_viewer.setFont(QFont("Courier New", 10))
        details_layout.addWidget(self.context_viewer)
        
        self.tabs.addTab(details_widget, "Details")
        
        # Statistics tab
        stats_widget = QWidget()
        stats_layout = QVBoxLayout(stats_widget)
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        stats_layout.addWidget(self.stats_text)
        self.tabs.addTab(stats_widget, "Statistics")
        
        layout.addWidget(self.tabs)
        
        # Store scan results
        self.current_issues = []
        
        # Connect tree item selection
        self.results_tree.itemClicked.connect(self.show_context)
        
    def select_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.dir_label.setText(directory)
            self.scan_btn.setEnabled(True)
            
    def start_scan(self):
        directory = self.dir_label.text()
        if not directory or directory == "No directory selected":
            return
            
        self.scan_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("Scanning...")
        self.results_tree.clear()
        self.context_viewer.clear()
        self.summary_text.clear()
        self.stats_text.clear()
        
        # Start scan in background
        self.scan_thread = ScanWorker(directory, None)
        self.scan_thread.finished.connect(self.scan_completed)
        self.scan_thread.status_update.connect(self.update_status)
        self.scan_thread.start()
        
        # Start progress animation
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_progress)
        self.progress_timer.start(100)
        
    def update_progress(self):
        current = self.progress_bar.value()
        if current >= 100:
            current = 0
        self.progress_bar.setValue(current + 1)
        
    def update_status(self, message):
        self.status_label.setText(message)
        
    def scan_completed(self, issues):
        self.progress_timer.stop()
        self.progress_bar.setValue(100)
        self.scan_btn.setEnabled(True)
        self.status_label.setText("Scan completed")
        self.current_issues = issues
        
        # Update results
        self.update_summary(issues)
        self.update_details(issues)
        self.update_statistics(issues)
        
    def update_summary(self, issues):
        summary = []
        severity_counts = {s: 0 for s in Severity}
        
        for issue in issues:
            severity_counts[issue.severity] += 1
            
        summary.append("Scan Summary")
        summary.append("=" * 50)
        summary.append(f"Total Issues Found: {len(issues)}")
        summary.append("\nSeverity Breakdown:")
        for severity, count in severity_counts.items():
            if count > 0:
                summary.append(f"- {severity.value}: {count}")
                
        self.summary_text.setText("\n".join(summary))
        
    def update_details(self, issues):
        self.results_tree.clear()
        
        for issue in issues:
            item = QTreeWidgetItem([
                str(issue.file_path),
                str(issue.line_number),
                issue.severity.value,
                issue.description
            ])
            
            # Color code by severity
            color = {
                Severity.CRITICAL: QColor("#ff0000"),
                Severity.HIGH: QColor("#ff6b6b"),
                Severity.MEDIUM: QColor("#ffd93d"),
                Severity.LOW: QColor("#6bff6b")
            }.get(issue.severity, QColor("#ffffff"))
            
            item.setForeground(2, color)
            self.results_tree.addTopLevelItem(item)
            
    def update_statistics(self, issues):
        stats = []
        
        # File type statistics
        file_types = {}
        for issue in issues:
            file_type = issue.file_type
            file_types[file_type] = file_types.get(file_type, 0) + 1
            
        stats.append("File Type Statistics")
        stats.append("=" * 50)
        for file_type, count in file_types.items():
            stats.append(f"{file_type}: {count} issues")
            
        # Pattern statistics
        patterns = {}
        for issue in issues:
            patterns[issue.pattern_name] = patterns.get(issue.pattern_name, 0) + 1
            
        stats.append("\nPattern Statistics")
        stats.append("=" * 50)
        for pattern, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True):
            stats.append(f"{pattern}: {count} occurrences")
            
        self.stats_text.setText("\n".join(stats))
        
    def show_context(self, item):
        file_path = item.text(0)
        line_number = int(item.text(1))
        
        # Find the corresponding issue
        for issue in self.current_issues:
            if str(issue.file_path) == file_path and issue.line_number == line_number:
                self.context_viewer.setText(issue.context)
                break
                
    def filter_results(self):
        selected_severity = self.severity_filter.currentText()
        
        if selected_severity == "All":
            self.update_details(self.current_issues)
        else:
            filtered_issues = [
                issue for issue in self.current_issues 
                if issue.severity.value == selected_severity
            ]
            self.update_details(filtered_issues)

def main():
    app = QApplication(sys.argv)
    window = SecurityScannerGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
