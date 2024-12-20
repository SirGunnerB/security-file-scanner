import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget, 
    QLabel, QFileDialog, QStatusBar, QMessageBox, QProgressBar, QTextEdit, QHBoxLayout, QAction, QMenu
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
import time  # Simulating scan delay

class ScannerThread(QThread):
    """Thread for running the scanner to keep the GUI responsive."""
    update_progress = pyqtSignal(int)
    scan_complete = pyqtSignal(list)

    def __init__(self, files):
        super().__init__()
        self.files = files

    def run(self):
        """Run the scanning process."""
        results = []
        total_files = len(self.files)
        for i, file in enumerate(self.files):
            time.sleep(1)  # Simulate scanning time
            results.append(f"Scanned {file}: No issues found.")  # Simulated result
            self.update_progress.emit(int((i + 1) / total_files * 100))
        self.scan_complete.emit(results)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.create_status_bar()

    def setup_ui(self):
        """Set up the main user interface."""
        self.setWindowTitle('Security File Scanner')
        self.setGeometry(100, 100, 800, 600)

        # Central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Layout
        self.layout = QVBoxLayout()
        self.central_widget.setLayout(self.layout)

        # Header
        self.header_label = QLabel('Security File Scanner')
        self.header_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.header_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #007AFF;")
        self.layout.addWidget(self.header_label)

        # Scan Button
        self.scan_button = self.create_button('Start Scan', self.start_scan)
        self.layout.addWidget(self.scan_button)

        # File Selection
        self.file_label = QLabel('No files selected')
        self.file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.file_label.setStyleSheet("font-size: 16px; color: #333;")
        self.layout.addWidget(self.file_label)

        self.select_file_button = self.create_button('Select File/Folder', self.select_file)
        self.layout.addWidget(self.select_file_button)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.layout.addWidget(self.progress_bar)

        # Log Output
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.layout.addWidget(self.log_output)

        # Menu Bar
        self.create_menu()

    def create_button(self, text, callback):
        """Create a button with specified text and callback."""
        button = QPushButton(text)
        button.setStyleSheet("background-color: #007AFF; color: white; border-radius: 10px; padding: 10px;")
        button.clicked.connect(callback)
        return button

    def create_status_bar(self):
        """Create a status bar for displaying messages."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

    def create_menu(self):
        """Create a menu bar with options."""
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu('File')

        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.confirm_exit)
        file_menu.addAction(exit_action)

    def start_scan(self):
        """Start the scanning process."""
        selected_files = self.file_label.text()
        if selected_files == 'No files selected':
            self.show_error_message("Please select a file or folder before starting the scan.")
            return
        
        self.file_label.setText('Scan started...')
        self.status_bar.showMessage('Scanning in progress...', 2000)
        self.progress_bar.setValue(0)

        # Start the scanning thread
        files_to_scan = selected_files.split('; ')  # Assuming multiple files are separated by '; '
        self.scanner_thread = ScannerThread(files_to_scan)
        self.scanner_thread.update_progress.connect(self.update_progress)
        self.scanner_thread.scan_complete.connect(self.display_results)
        self.scanner_thread.start()

    def select_file(self):
        """Open a file dialog to select a file or folder."""
        file_names, _ = QFileDialog.getOpenFileNames(self, 'Select File(s)', '', 'All Files (*)')
        if file_names:
            self.file_label.setText('; '.join(file_names))
        else:
            self.status_bar.showMessage('No files selected.', 2000)

    def show_error_message(self, message: str):
        """Display an error message dialog."""
        QMessageBox.critical(self, 'Error', message)

    def update_progress(self, value: int):
        """Update the progress bar."""
        self.progress_bar.setValue(value)

    def display_results(self, results: list):
        """Display the scan results in the log output."""
        self.log_output.clear()
        self.log_output.append("Scan Results:\n")
        for result in results:
            self.log_output.append(result)
        self.file_label.setText('Scan completed successfully!')
        self.status_bar.showMessage('Scan finished.', 2000)

    def confirm_exit(self):
        """Prompt the user for confirmation before exiting."""
        reply = QMessageBox.question(self, 'Confirm Exit', 'Are you sure you want to exit?',
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            QApplication.quit()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())