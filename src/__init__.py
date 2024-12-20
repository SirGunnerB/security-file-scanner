"""
Security File Scanner
A tool for detecting potentially malicious patterns in source code.

Author: SirGunnerB
License: MIT
"""

__version__ = "1.0.0"
__author__ = "SirGunnerB"
__license__ = "MIT"

from typing import Dict, List, Optional

# Package-level configuration
DEFAULT_CONFIG: Dict[str, any] = {
    "scan_depth": 5,
    "max_file_size": 1024 * 1024 * 10,  # 10MB
    "ignore_patterns": [".git", "__pycache__", "venv"],
    "parallel_scan": True,
    "log_level": "INFO"
}

# Public API
from .scanner import scan_file, scan_directory
from .patterns import load_patterns
from .reporting import generate_report
from .gui import launch_gui

__all__ = [
    "scan_file",
    "scan_directory",
    "load_patterns",
    "generate_report",
    "launch_gui",
    "DEFAULT_CONFIG"
]

def get_version() -> str:
    """Return the current version of the package."""
    return __version__

def configure(config: Optional[Dict] = None) -> None:
    """Configure global scanner settings."""
    global DEFAULT_CONFIG
    if config:
        DEFAULT_CONFIG.update(config)
