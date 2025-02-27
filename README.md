# Security File Scanner

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-1.0.0-orange)

A comprehensive security scanning tool to detect potential vulnerabilities in source code files, featuring both CLI and GUI interfaces.

## Table of Contents

- [Features](#features)
- [Security Checks](#security-checks)
- [Installation](#installation)
- [Usage](#usage)
  - [GUI Interface](#gui-interface)
  - [CLI Interface](#cli-interface)
- [Severity Levels](#severity-levels)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)
- [Contact](#contact)

## Features

- 🔍 Multi-file scanning with parallel processing
- 🎯 Extensive security pattern detection
- 📊 Severity-based issue classification
- 💻 Modern GUI interface with real-time progress tracking
- 🌈 Rich text console output
- 📝 Detailed context reporting
- 🔄 File type detection and binary file handling

## Security Checks

- Code Execution Risks
- System Commands
- File Operations
- Network Activities
- Data Handling
- Cryptographic Weaknesses
- Sensitive Data Exposure
- Input Validation
- Error Handling
- Configuration Issues

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/security-file-scanner.git
   cd security-file-scanner
   ```

2. (Optional) Set up a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. Install dependencies:
   ```bash
   python3 -m pip install -r requirements.txt
   ```

4. Install libmagic (for file type detection):
   - macOS: `brew install libmagic`
   - Linux: `sudo apt-get install libmagic1`
   - Windows: Download from [Windows Binaries](https://github.com/pidydx/libmagicwin64)

## Usage

### GUI Interface

Run the GUI scanner:
```bash
python3 src/gui_scanner.py
```

1. Click "Select Directory" to choose a directory to scan.
2. Click "Start Scan" to begin the analysis.
3. View results in three tabs:
   - **Summary**: Overall statistics
   - **Details**: Interactive issue list with context
   - **Statistics**: Detailed breakdown

**Example Output**:
```
Summary:
- Total Files Scanned: 100
- Issues Found: 5
```

### CLI Interface

Run the CLI scanner:
```bash
python3 src/cli_scanner.py /path/to/directory
```

**Example Output**:
```
Scanning directory: /path/to/directory
Found 3 issues in file.py:
- Line 10: Dangerous eval() function detected
```

## Severity Levels

- 🔴 **CRITICAL**: Immediate security risk
- 🟠 **HIGH**: Significant vulnerability
- 🟡 **MEDIUM**: Potential security concern
- 🟢 **LOW**: Minor security observation

## Contributing

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/YourFeature`
3. Commit your changes: `git commit -am 'Add YourFeature'`
4. Push to the branch: `git push origin feature/YourFeature`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with PyQt6 for the GUI interface
- Uses python-magic for file type detection
- Rich library for console formatting

## Contact

For any questions or issues, please contact:
- **Your Name**: [your.email@example.com](mailto:your.email@example.com)
- **GitHub**: [yourusername](https://github.com/yourusername)
