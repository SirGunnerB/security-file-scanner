import os
from pathlib import Path
from security_scanner import SecurityScanner, SecurityIssue
from typing import List

def main():
    # Create an instance of the SecurityScanner
    scanner = SecurityScanner(max_file_size=10 * 1024 * 1024)  # 10MB limit

    # Define the path to the test file
    test_file_path = Path(__file__).parent / 'test_file.py'

    # Check if the test file exists
    if not test_file_path.is_file():
        print(f"Test file not found: {test_file_path}")
        return

    # Scan the test file
    issues: List[SecurityIssue] = scanner.scan_file(test_file_path)

    # Print the results
    scanner.print_results(issues)

if __name__ == "__main__":
    main()