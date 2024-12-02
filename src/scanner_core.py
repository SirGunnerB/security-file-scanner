from enum import Enum
from dataclasses import dataclass
from pathlib import Path
import re
from typing import List, Dict, Optional, Set
import multiprocessing as mp
from datetime import datetime
import logging
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.syntax import Syntax
import magic  # for file type detection
import ast
from concurrent.futures import ThreadPoolExecutor
import hashlib

class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class SecurityIssue:
    file_path: str
    line_number: int
    pattern_name: str
    description: str
    severity: Severity
    matched_text: str
    context: str
    file_type: str
    file_hash: str

class SecurityPattern:
    def __init__(self, name: str, pattern: str, description: str, severity: Severity):
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        self.description = description
        self.severity = severity

class SecurityScanner:
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    BINARY_EXTENSIONS = {'.exe', '.dll', '.so', '.dylib', '.bin', '.pyc'}
    TEXT_EXTENSIONS = {'.py', '.js', '.php', '.java', '.cs', '.go', '.rb', '.pl', '.sh', 
                      '.txt', '.html', '.xml', '.json', '.yml', '.yaml', '.ini', '.cfg'}

    def __init__(self):
        self.console = Console()
        self.setup_logging()
        self._file_hashes: Dict[str, str] = {}

    @staticmethod
    def setup_logging():
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('security_scan.log'),
                logging.StreamHandler()
            ]
        )

    @staticmethod
    def _initialize_patterns() -> List[SecurityPattern]:
        return [
            # Code Execution
            SecurityPattern("eval_exec", r"eval\s*\([^)]*\)", "Dangerous eval() function detected", Severity.CRITICAL),
            SecurityPattern("exec_call", r"exec\s*\([^)]*\)", "Dangerous exec() function detected", Severity.CRITICAL),
            SecurityPattern("os_system", r"os\.system\s*\([^)]*\)", "OS command execution detected", Severity.HIGH),
            SecurityPattern("subprocess_shell", r"subprocess\..*\(.*shell\s*=\s*True", "Shell execution in subprocess", Severity.HIGH),
            
            # File Operations
            SecurityPattern("file_write", r"open\s*\([^)]*,\s*['\"][wa]['\"]", "File write operation detected", Severity.MEDIUM),
            SecurityPattern("file_delete", r"os\.(remove|unlink)\s*\([^)]*\)", "File deletion operation", Severity.MEDIUM),
            SecurityPattern("chmod", r"os\.chmod\s*\([^)]*\)", "File permission modification", Severity.MEDIUM),
            
            # Network Operations
            SecurityPattern("socket_creation", r"socket\.socket\s*\([^)]*\)", "Network socket creation", Severity.MEDIUM),
            SecurityPattern("http_request", r"(requests|urllib|http)\.(get|post|put|delete)", "HTTP request detected", Severity.LOW),
            SecurityPattern("ftp_operation", r"ftplib\.FTP\s*\([^)]*\)", "FTP operation detected", Severity.MEDIUM),
            
            # Data Handling
            SecurityPattern("pickle_usage", r"pickle\.(loads?|dumps?)", "Unsafe pickle operation", Severity.HIGH),
            SecurityPattern("yaml_load", r"yaml\.load\s*\([^)]*\)", "Potentially unsafe YAML load", Severity.HIGH),
            SecurityPattern("marshal_usage", r"marshal\.(loads?|dumps?)", "Marshal usage detected", Severity.HIGH),
            
            # Cryptography
            SecurityPattern("weak_crypto", r"hashlib\.(md5|sha1)", "Weak cryptographic algorithm", Severity.MEDIUM),
            SecurityPattern("random_usage", r"random\.(random|randint)", "Insecure random number generation", Severity.MEDIUM),
            SecurityPattern("weak_cipher", r"Crypto\.Cipher\.(DES|RC4|Blowfish)", "Weak cipher algorithm", Severity.HIGH),
            
            # Data Exposure
            SecurityPattern("hardcoded_secret", r"(password|secret|key|token|api[_-]?key)\s*=\s*['\"][^'\"]+['\"]", 
                          "Potential hardcoded secret", Severity.HIGH),
            SecurityPattern("sensitive_print", r"print\s*\([^)]*password[^)]*\)", "Printing sensitive information", Severity.MEDIUM),
            SecurityPattern("sensitive_log", r"log(ging)?\..*\([^)]*password[^)]*\)", "Logging sensitive information", Severity.MEDIUM),
            
            # Input Validation
            SecurityPattern("sql_injection", r"execute\s*\([^)]*\%[^)]*\)", "Potential SQL injection", Severity.CRITICAL),
            SecurityPattern("format_injection", r"format\s*\([^)]*\%[^)]*\)", "Format string vulnerability", Severity.HIGH),
            SecurityPattern("shell_injection", r"shell\s*=\s*True", "Shell injection vulnerability", Severity.HIGH),
            
            # Error Handling
            SecurityPattern("bare_except", r"except\s*:", "Bare except clause", Severity.LOW),
            SecurityPattern("pass_except", r"except.*:\s*pass", "Pass in except block", Severity.LOW),
            
            # Configuration
            SecurityPattern("debug_mode", r"DEBUG\s*=\s*True", "Debug mode enabled", Severity.LOW),
            SecurityPattern("all_hosts", r"host\s*=\s*['\"]0\.0\.0\.0['\"]", "Listening on all interfaces", Severity.MEDIUM),
        ]

    def get_file_hash(self, file_path: Path) -> str:
        """Calculate and cache file hash."""
        path_str = str(file_path)
        if path_str in self._file_hashes:
            return self._file_hashes[path_str]
        
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        
        file_hash = hash_md5.hexdigest()
        self._file_hashes[path_str] = file_hash
        return file_hash

    def get_file_type(self, file_path: Path) -> str:
        """Detect file type using magic."""
        try:
            return magic.from_file(str(file_path))
        except:
            return "unknown"

    def get_context(self, content: str, line_number: int, context_lines: int = 2) -> str:
        """Get surrounding lines of code with syntax highlighting."""
        lines = content.splitlines()
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)
        
        context_lines = lines[start:end]
        line_numbers = range(start + 1, end + 1)
        
        # Highlight the target line
        formatted_lines = []
        for i, (num, line) in enumerate(zip(line_numbers, context_lines)):
            prefix = "→ " if num == line_number else "  "
            formatted_lines.append(f"{prefix}{num:4d} | {line}")
        
        return "\n".join(formatted_lines)

    def scan_file(self, file_path: Path) -> List[SecurityIssue]:
        """Scan a single file for security issues."""
        try:
            # Skip files that are too large
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                logging.warning(f"Skipping {file_path}: exceeds size limit")
                return []

            # Get file type and hash
            file_type = self.get_file_type(file_path)
            file_hash = self.get_file_hash(file_path)

            # Skip binary files unless specifically included
            if file_path.suffix in self.BINARY_EXTENSIONS:
                logging.info(f"Skipping binary file: {file_path}")
                return []

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            issues = []
            for pattern in self._initialize_patterns():
                for match in pattern.pattern.finditer(content):
                    line_number = content[:match.start()].count('\n') + 1
                    context = self.get_context(content, line_number)
                    
                    issues.append(SecurityIssue(
                        file_path=str(file_path),
                        line_number=line_number,
                        pattern_name=pattern.name,
                        description=pattern.description,
                        severity=pattern.severity,
                        matched_text=match.group(),
                        context=context,
                        file_type=file_type,
                        file_hash=file_hash
                    ))
            return issues

        except Exception as e:
            logging.error(f"Error scanning {file_path}: {str(e)}")
            return []

    def scan_directory(self, directory: Path, extensions: Optional[Set[str]] = None) -> List[SecurityIssue]:
        """Scan a directory using multiple processes with progress tracking."""
        if extensions is None:
            extensions = self.TEXT_EXTENSIONS

        # Collect files to scan
        files_to_scan = []
        for ext in extensions:
            files_to_scan.extend(directory.rglob(f"*{ext}"))
        
        files_to_scan = list(files_to_scan)  # Convert to list for length
        
        if not files_to_scan:
            self.console.print("[yellow]No matching files found to scan[/yellow]")
            return []

        results = []
        with Progress(
            SpinnerColumn(),
            *Progress.get_default_columns(),
            TimeElapsedColumn(),
            console=self.console
        ) as progress:
            task = progress.add_task("[cyan]Scanning files...", total=len(files_to_scan))
            
            with ThreadPoolExecutor(max_workers=mp.cpu_count()) as executor:
                futures = []
                for file_path in files_to_scan:
                    future = executor.submit(self.scan_file, file_path)
                    futures.append(future)
                
                for future in futures:
                    result = future.result()
                    results.extend(result)
                    progress.advance(task)

        return results

    def format_severity(self, severity: Severity) -> str:
        """Format severity level with appropriate color."""
        colors = {
            Severity.LOW: "blue",
            Severity.MEDIUM: "yellow",
            Severity.HIGH: "red",
            Severity.CRITICAL: "bold red"
        }
        return f"[{colors[severity]}]{severity.value}[/{colors[severity]}]"

    def print_results(self, issues: List[SecurityIssue]):
        """Print scan results in a formatted way."""
        if not issues:
            self.console.print("[green]✓ No security issues found![/green]")
            return

        # Group by severity
        issues_by_severity = {}
        for issue in issues:
            if issue.severity not in issues_by_severity:
                issues_by_severity[issue.severity] = []
            issues_by_severity[issue.severity].append(issue)

        # Print summary
        self.console.print("\n[bold]Security Scan Summary:[/bold]")
        for severity in Severity:
            count = len(issues_by_severity.get(severity, []))
            if count > 0:
                self.console.print(f"{self.format_severity(severity)}: {count} issues")

        # Print detailed findings
        self.console.print("\n[bold]Detailed Findings:[/bold]")
        for severity in Severity:
            if severity not in issues_by_severity:
                continue

            self.console.print(f"\n{self.format_severity(severity)} Severity Issues:")
            for issue in issues_by_severity[severity]:
                self.console.print(f"\n[bold]File:[/bold] {issue.file_path}")
                self.console.print(f"[bold]Type:[/bold] {issue.file_type}")
                self.console.print(f"[bold]Line {issue.line_number}:[/bold] {issue.description}")
                self.console.print("[bold]Context:[/bold]")
                self.console.print(issue.context)
                self.console.print("  " + "-" * 50)
