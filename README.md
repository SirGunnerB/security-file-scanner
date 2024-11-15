# Security File Scanner

A Python-based security scanner for analyzing files and detecting potentially malicious code patterns.

## ?? Disclaimer

This tool is provided for educational and research purposes only. It is designed to help identify potentially suspicious code patterns, but:

- It is NOT a replacement for professional security auditing tools
- It may produce false positives or miss actual malicious code
- No warranty or guarantee is provided about its effectiveness
- Users are responsible for verifying all findings
- Always review code manually and use multiple security tools
- Do not use this as your only security measure

## Features

- Scan individual files or entire directories
- Detect potentially dangerous code patterns
- Real-time scanning statistics
- Progress tracking
- Save detailed reports
- Dark theme UI

## ?? Installation

1. Clone the repository:
\\\ash
git clone https://github.com/SirGunnerB/security-file-scanner.git
cd security-file-scanner
\\\

2. Create a virtual environment:
\\\ash
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
\\\

3. Install dependencies:
\\\ash
pip install -r requirements.txt
\\\

## ?? Step-by-Step Usage Guide

### Starting the Application

1. Run the scanner:
\\\ash
python src/malware_scanner.py
\\\
   Or use the executable from the dist folder if you've built it.

### Scanning Files

1. **Single File Scan:**
   - Click "Select File" button
   - Navigate to the file you want to scan
   - Select file and click "Open"
   - Wait for scan to complete
   - Review results in the main window

2. **Folder Scan:**
   - Click "Select Folder" button
   - Choose the folder you want to scan
   - Click "Select Folder"
   - Monitor progress bar
   - Review results as they appear

### Understanding Results

The scanner checks for several suspicious patterns:
- Code execution (eval, exec)
- System commands
- Network activity
- Encryption operations
- Base64 encoding
- And more...

Results are color-coded:
- ?? Red: Warnings about suspicious code
- ?? Blue: Code snippets
- ?? Green: Information messages

### Saving Reports

1. After scan completion:
   - Click "Save Report" button
   - Choose save location
   - Select report format
   - Click "Save"

### Interpreting Findings

1. **Warning Messages:**
   - Show the type of suspicious pattern
   - Include file location
   - Display the suspicious code

2. **Statistics:**
   - Total files scanned
   - Number of issues found
   - Scan duration

## ?? Building Executable

To create a standalone executable:

\\\ash
pyinstaller --onefile --windowed --name "SecurityFileScanner" src/malware_scanner.py
\\\

The executable will be created in the \dist\ directory.

## ?? What It Detects

The scanner looks for potentially suspicious patterns including:

1. Code Execution:
   - eval() functions
   - exec() functions
   - Dynamic code loading

2. System Access:
   - OS command execution
   - System modifications
   - Process creation

3. Network Activity:
   - Socket connections
   - HTTP requests
   - Network access

4. Suspicious Operations:
   - Base64 encoding/decoding
   - Encryption operations
   - File system operations

## ? Best Practices

1. Always scan in a safe environment
2. Keep the scanner updated
3. Verify findings manually
4. Use multiple security tools
5. Follow your organization's security policies

## ?? Troubleshooting

Common issues and solutions:

1. **Scanner won't start:**
   - Check Python installation
   - Verify dependencies are installed
   - Run from command line to see errors

2. **Scan fails:**
   - Check file permissions
   - Ensure files are readable
   - Verify file encodings

3. **No results showing:**
   - Check file types being scanned
   - Verify patterns being searched
   - Look for error messages

## License

MIT License - see LICENSE file for details.

## Author

SirGunnerB

## ?? Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ?? Support

If you encounter any issues or have questions:
1. Check the troubleshooting guide
2. Open an issue on GitHub
3. Contact the maintainer

---

**Note:** This tool is continuously evolving. Check back for updates and new features.

## ?? Screenshots

*Screenshots coming soon! The application includes:*

- Dark-themed main interface
- Real-time scanning progress
- Syntax-highlighted results
- Report generation dialog

