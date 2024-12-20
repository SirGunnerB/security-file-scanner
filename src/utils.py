import hashlib
from pathlib import Path
from datetime import datetime
import logging
import magic
import os

class ScanUtils:
    @staticmethod
    def calculate_file_hash(file_path: str) -> str:
        """Calculate MD5 hash of a file."""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            logging.info(f"Calculated hash for {file_path}")
            return hash_md5.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating hash for {file_path}: {str(e)}")
            return ""

    @staticmethod
    def get_file_info(file_path: str) -> dict:
        """Get basic file information."""
        path = Path(file_path)
        try:
            stats = path.stat()
            file_info = {
                'name': path.name,
                'size': stats.st_size,
                'created': datetime.fromtimestamp(stats.st_ctime),
                'modified': datetime.fromtimestamp(stats.st_mtime),
                'extension': path.suffix,
                'path': str(path.absolute()),
                'type': ScanUtils.get_file_type(file_path)
            }
            logging.info(f"Retrieved info for {file_path}")
            return file_info
        except Exception as e:
            logging.error(f"Error getting info for {file_path}: {str(e)}")
            return {}

    @staticmethod
    def get_file_type(file_path: str) -> str:
        """Detect file type using magic."""
        try:
            return magic.from_file(file_path)
        except Exception as e:
            logging.error(f"Error detecting file type for {file_path}: {str(e)}")
            return "unknown"

    @staticmethod
    def is_file_readable(file_path: str) -> bool:
        """Check if a file is readable."""
        path = Path(file_path)
        readable = path.is_file() and os.access(path, os.R_OK)
        logging.info(f"File {file_path} is {'readable' if readable else 'not readable'}")
        return readable

    @staticmethod
    def setup_logging():
        """Setup logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('scanner.log'),
                logging.StreamHandler()
            ]
        )
