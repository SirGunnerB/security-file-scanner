# Security File Scanner - Installation Guide

## System Requirements

### Minimum Requirements
- CPU: Dual-core processor
- RAM: 4GB
- Storage: 500MB free space
- Display: 1280x720 resolution

### Software Prerequisites
| Component | Minimum Version | Recommended Version |
|-----------|----------------|-------------------|
| Python    | 3.10          | 3.12             |
| Git       | 2.0           | 2.43             |
| pip       | 21.0          | 24.0             |
| PyQt6     | 6.0           | 6.6              |

## Quick Install

### Windows (PowerShell)
```powershell
# One-line installation
irm https://install.security-scanner.dev/windows | iex
```

### Linux/Mac
```bash
# One-line installation
curl -fsSL https://install.security-scanner.dev/unix | bash
```

## Manual Installation

### Windows

1. **Install Python**
```powershell
# Using winget
winget install Python.Python.3.12
# Verify installation
python --version
```

2. **Install Git**
```powershell
winget install Git.Git
# Verify installation
git --version
```

3. **Clone & Setup**
```powershell
# Clone repository
git clone https://github.com/SirGunnerB/security-file-scanner.git
cd security-file-scanner

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install pyqt6
```

### Linux

1. **Install Dependencies**
```bash
# Ubuntu/Debian
sudo apt update && sudo apt install -y \
    python3.12 \
    python3-pip \
    python3-venv \
    git \
    build-essential

# Fedora
sudo dnf install -y \
    python3.12 \
    python3-pip \
    python3-virtualenv \
    git \
    gcc
```

2. **Clone & Setup**
```bash
# Clone repository
git clone https://github.com/SirGunnerB/security-file-scanner.git
cd security-file-scanner

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install pyqt6
```

### macOS

1. **Install Dependencies**
```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required packages
brew install python@3.12 git
```

2. **Clone & Setup**
```bash
# Clone repository
git clone https://github.com/SirGunnerB/security-file-scanner.git
cd security-file-scanner

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install pyqt6
```

## Verification

Test your installation:
```bash
# In the project directory with venv activated
python -m pytest tests/
python scripts/verify_install.py
```

## Troubleshooting

### Common Issues

1. **Python Path Issues**
```bash
# Add to PATH on Windows
setx PATH "%PATH%;C:\Python312"

# Add to PATH on Unix
echo 'export PATH=$PATH:/usr/local/bin/python3' >> ~/.bashrc
source ~/.bashrc
```

2. **Permission Errors**
```bash
# Windows: Run PowerShell as Administrator
# Linux/Mac: Use sudo for system directories
sudo pip install -r requirements.txt
```

3. **PyQt6 Installation Fails**
```bash
# Windows
pip install --upgrade pip wheel setuptools
pip install pyqt6 --force-reinstall

# Linux
sudo apt install python3-pyqt6  # Ubuntu/Debian
sudo dnf install python3-qt6    # Fedora
```

## Update Instructions

```bash
# In project directory
git pull origin main
pip install -r requirements.txt --upgrade
```

## Uninstallation

```bash
# Windows
rmdir /s /q security-file-scanner
pip uninstall -r requirements.txt -y

# Linux/Mac
rm -rf security-file-scanner
pip uninstall -r requirements.txt -y
```

## Support

- GitHub Issues: [Report a Problem](https://github.com/SirGunnerB/security-file-scanner/issues)
- Documentation: [Read the Docs](https://docs.security-scanner.dev)
- Community: [Join Discord](https://discord.gg/security-scanner)
