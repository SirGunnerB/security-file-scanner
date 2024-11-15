import hashlib
from pathlib import Path
from datetime import datetime
import logging

class ScanUtils:
    @staticmethod
    def calculate_file_hash(file_path):
        """Calculate MD5 hash of a file."""
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

    @staticmethod
    def get_file_info(file_path):
        """Get basic file information."""
        path = Path(file_path)
        stats = path.stat()
        return {
            'name': path.name,
            'size': stats.st_size,
            'created': datetime.fromtimestamp(stats.st_ctime),
            'modified': datetime.fromtimestamp(stats.st_mtime),
            'extension': path.suffix,
            'path': str(path.absolute())
        }

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
