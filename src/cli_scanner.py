#!/usr/bin/env python3
import sys
from pathlib import Path
from datetime import datetime
from scanner_core import SecurityScanner
from rich.console import Console

def main():
    console = Console()
    scanner = SecurityScanner()
    
    # Get target path
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = "."
    
    path = Path(target)
    
    # Print scan start
    console.print(f"\n[bold blue]Starting security scan of[/bold blue] [bold white]{path}[/bold white]")
    console.print(f"[dim]Scan started at {datetime.now()}[/dim]\n")
    
    try:
        # Perform scan
        extensions = ['.py', '.js', '.php', '.rb', '.java', '.cs', '.go']
        if path.is_file():
            results = scanner.scan_file(path)
        else:
            results = scanner.scan_directory(path, extensions)
        
        # Print results
        scanner.print_results(results)
        
        # Print statistics
        console.print(f"\n[dim]Scan completed at {datetime.now()}[/dim]")
        console.print(f"[dim]Total files scanned: {len(set(r.file_path for r in results))}[/dim]")
        console.print(f"[dim]Total issues found: {len(results)}[/dim]")
        
    except Exception as e:
        console.print(f"[bold red]Error during scan:[/bold red] {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
