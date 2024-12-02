import re
from pathlib import Path
from datetime import datetime
import multiprocessing as mp
from typing import Dict, List, Optional, Tuple
import logging
from dataclasses import dataclass
from enum import Enum
import hashlib
import ast

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class ScanResult:
    file_path: str
    line_number: int
    category: str
    description: str
    severity: Severity
    pattern_match: str
    context: str
    file_hash: str

class ScanEngine:
    def __init__(self, max_file_size: int = 10_000_000):  # 10MB default limit
        self.max_file_size = max_file_size
        self.file_hashes = {}  # Cache of file hashes
        self.setup_logging()

    @staticmethod
    def setup_logging():
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('scanner.log'),
                logging.StreamHandler()
            ]
        )

    def get_file_hash(self, file_path: Path) -> str:
        """Calculate and cache file hash."""
        if str(file_path) in self.file_hashes:
            return self.file_hashes[str(file_path)]
        
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        
        file_hash = hash_md5.hexdigest()
        self.file_hashes[str(file_path)] = file_hash
        return file_hash

    def get_line_context(self, content: str, line_number: int, context_lines: int = 2) -> str:
        """Get surrounding lines of code for context."""
        lines = content.splitlines()
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        return '\n'.join(lines[start:end])

    def is_comment_line(self, line: str) -> bool:
        """Check if a line is a comment."""
        return line.strip().startswith('#')

    def is_in_docstring(self, content: str, position: int) -> bool:
        """Check if position is within a docstring."""
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Str) and isinstance(node.parent, (ast.Expr, ast.Assign)):
                    if node.lineno <= position <= node.end_lineno:
                        return True
        except:
            return False
        return False

    def scan_file(self, file_path: Path) -> List[ScanResult]:
        """Scan a single file for security issues."""
        try:
            # Check file size
            if file_path.stat().st_size > self.max_file_size:
                logging.warning(f"File {file_path} exceeds size limit of {self.max_file_size} bytes")
                return []

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            results = []
            file_hash = self.get_file_hash(file_path)

            for category, patterns in SCAN_PATTERNS.items():
                for pattern, description, severity in patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        line_number = content[:match.start()].count('\n') + 1
                        line = content.splitlines()[line_number - 1]

                        # Skip if in comment or docstring
                        if self.is_comment_line(line) or self.is_in_docstring(content, line_number):
                            continue

                        results.append(ScanResult(
                            file_path=str(file_path),
                            line_number=line_number,
                            category=category,
                            description=description,
                            severity=severity,
                            pattern_match=match.group(),
                            context=self.get_line_context(content, line_number),
                            file_hash=file_hash
                        ))

            return results

        except Exception as e:
            logging.error(f"Error scanning {file_path}: {str(e)}")
            return []

    def scan_directory(self, directory: Path, extensions: List[str]) -> List[ScanResult]:
        """Scan a directory using multiple processes."""
        files_to_scan = []
        for ext in extensions:
            files_to_scan.extend(directory.rglob(f"*{ext}"))

        with mp.Pool() as pool:
            results = pool.map(self.scan_file, files_to_scan)

        # Flatten results
        return [item for sublist in results for item in sublist]

# Enhanced patterns with severity levels
SCAN_PATTERNS = {
    'code_execution': [
        (r'eval\s*\([^)]*\)', 'Arbitrary code execution', Severity.CRITICAL),
        (r'exec\s*\([^)]*\)', 'Arbitrary code execution', Severity.CRITICAL),
        (r'execfile\s*\([^)]*\)', 'Arbitrary code execution', Severity.CRITICAL),
        (r'__import__\s*\([^)]*\)', 'Dynamic import', Severity.HIGH),
    ],
    
    'system_commands': [
        (r'os\.system\s*\([^)]*\)', 'System command execution', Severity.HIGH),
        (r'subprocess\..*\([^)]*shell\s*=\s*True[^)]*\)', 'Shell execution in subprocess', Severity.HIGH),
        (r'subprocess\..*call\s*\([^)]*\)', 'Process execution', Severity.MEDIUM),
    ],
    
    'network': [
        (r'socket\.socket\s*\([^)]*\)', 'Raw socket creation', Severity.MEDIUM),
        (r'urllib\.request\.urlopen\s*\([^)]*\)', 'URL request', Severity.LOW),
        (r'requests\.(get|post|put|delete)\s*\([^)]*\)', 'HTTP request', Severity.LOW),
    ],
    
    'file_operations': [
        (r'open\s*\([^)]*[\'"]w[\'"][^)]*\)', 'File write operation', Severity.MEDIUM),
        (r'open\s*\([^)]*[\'"]a[\'"][^)]*\)', 'File append operation', Severity.MEDIUM),
        (r'shutil\.(copy|move|rmtree)\s*\([^)]*\)', 'File system operation', Severity.MEDIUM),
    ],
    
    'data_handling': [
        (r'pickle\.(loads|load)\s*\([^)]*\)', 'Unsafe deserialization', Severity.CRITICAL),
        (r'yaml\.load\s*\([^)]*\)', 'Unsafe YAML loading', Severity.HIGH),
        (r'json\.loads?\s*\([^)]*\)', 'JSON parsing', Severity.LOW),
    ],
    
    'crypto_operations': [
        (r'random\.(random|randint)', 'Weak random number generation', Severity.MEDIUM),
        (r'hashlib\.md5\s*\([^)]*\)', 'Weak hashing algorithm (MD5)', Severity.MEDIUM),
        (r'hashlib\.sha1\s*\([^)]*\)', 'Weak hashing algorithm (SHA1)', Severity.MEDIUM),
    ],
    
    'data_exposure': [
        (r'(api|secret|key|token|password|credential).*=.*[\'"][^\'"]+[\'"]', 'Potential hardcoded secret', Severity.HIGH),
        (r'base64\.(encode|decode)\s*\([^)]*\)', 'Base64 encoding/decoding', Severity.LOW),
        (r'print\s*\([^)]*password[^)]*\)', 'Password logging', Severity.MEDIUM),
    ]
}
