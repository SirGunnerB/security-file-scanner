# Detailed Installation Guide

## Prerequisites
- Python 3.8 or higher
- Git
- pip (Python package manager)

## Windows Installation
1. Install Python:
   - Download from Microsoft Store or python.org
   - Check 'Add Python to PATH'
   - Verify with `python --version`

2. Install Git:
   - Download from git-scm.com
   - Use default settings
   - Verify with `git --version`

3. Clone Repository:
   ```powershell
   git clone https://github.com/SirGunnerB/security-file-scanner.git
   cd security-file-scanner
   ```

4. Setup Virtual Environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\activate
   pip install -r requirements.txt
   ```

## Linux/Mac Installation
1. Install Python:
   ```bash
   # Ubuntu/Debian
   sudo apt update
   sudo apt install python3 python3-venv python3-pip

   # Mac
   brew install python3
   ```

2. Clone and Setup:
   ```bash
   git clone https://github.com/SirGunnerB/security-file-scanner.git
   cd security-file-scanner
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
