"""
Configuration settings for the Security File Scanner.

This module contains scan patterns, UI settings, and file extensions
used by the scanner. It is designed to be easily extensible and maintainable.
"""

from typing import Dict, List, Tuple

# Type aliases for better readability
ScanPattern = Tuple[str, str]
ScanPatterns = Dict[str, List[ScanPattern]]
TextColors = Dict[str, str]

# Scan patterns for detecting potentially malicious code
SCAN_PATTERNS: ScanPatterns = {
    'code_execution': [
        (r'eval\s*\(.*\)', 'Potential arbitrary code execution'),
        (r'exec\s*\(.*\)', 'Potential arbitrary code execution'),
        (r'execfile\s*\(.*\)', 'Potential arbitrary code execution'),
    ],
    
    'system_commands': [
        (r'os\.system\s*\(.*\)', 'System command execution'),
        (r'subprocess\..*\(.*\)', 'Process execution'),
        (r'shell=True', 'Shell execution in subprocess'),
    ],
    
    'network': [
        (r'socket\..*\(.*\)', 'Network activity detected'),
        (r'urllib\..*\(.*\)', 'Network activity detected'),
        (r'requests\..*\(.*\)', 'Network activity detected'),
    ],
    
    'file_operations': [
        (r'open\s*\(.*,.*[\"\']+w[\"\'].*\)', 'File write operation'),
        (r'open\s*\(.*,.*[\"\']+a[\"\'].*\)', 'File append operation'),
        (r'shutil\..*\(.*\)', 'File system operation'),
    ],
    
    'data_exfiltration': [
        (r'base64\..*encode.*\(.*\)', 'Potential data encoding'),
        (r'crypto', 'Cryptographic operations'),
        (r'\.encrypt\(.*\)', 'Encryption operation'),
    ]
}

# User Interface settings for the scanner
UI_SETTINGS: Dict[str, any] = {
    'window_size': '1200x800',  # Default window size
    'theme': 'arc',              # Default theme
    'syntax_theme': 'monokai',   # Syntax highlighting theme
    'text_colors': {
        'warning': '#ff6b6b',    # Color for warnings
        'code': '#61afef',       # Color for code
        'info': '#98c379'        # Color for informational messages
    }
}

# Supported file extensions for scanning
FILE_EXTENSIONS: List[str] = [
    '.py', '.js', '.lua', '.dll', '.exe', 
    '.jar', '.json', '.xml', '.cfg', '.ini'
]

def get_supported_extensions() -> List[str]:
    """Return a list of supported file extensions for scanning."""
    return FILE_EXTENSIONS

def get_ui_settings() -> Dict[str, any]:
    """Return the UI settings for the scanner."""
    return UI_SETTINGS

def get_scan_patterns() -> ScanPatterns:
    """Return the scan patterns for detecting malicious code."""
    return SCAN_PATTERNS
