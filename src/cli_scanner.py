#!/usr/bin/env python3
"""
Command Line Interface for Security File Scanner
"""

import sys
from pathlib import Path
from datetime import datetime
from scanner_core import SecurityScanner
from rich.console import Console

def main():
    console = Console()
    scanner = SecurityScanner()
    
    # Get target path from command line arguments or default to current directory
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    path = Path(target)
    
    # Print scan start message
    console.print(f"\n[bold blue]Starting security scan of[/bold blue] [bold white]{path}[/bold white]")
    console.print(f"[dim]Scan started at {datetime.now()}[/dim]\n")
    
    try:
        # Define file extensions to scan
        extensions = ['.py', '.js', '.php', '.rb', '.java', '.cs', '.go']
        
        # Perform scan based on whether the path is a file or directory
        results = scanner.scan_file(path) if path.is_file() else scanner.scan_directory(path, extensions)
        
        # Print scan results
        scanner.print_results(results)
        
        # Print scan statistics
        console.print(f"\n[dim]Scan completed at {datetime.now()}[/dim]")
        console.print(f"[dim]Total files scanned: {len(set(r.file_path for r in results))}[/dim]")
        console.print(f"[dim]Total issues found: {len(results)}[/dim]")
        
    except Exception as e:
        console.print(f"[bold red]Error during scan:[/bold red] {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
