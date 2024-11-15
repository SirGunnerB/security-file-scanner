SCAN_PATTERNS = {
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

UI_SETTINGS = {
    'window_size': '1200x800',
    'theme': 'arc',
    'syntax_theme': 'monokai',
    'text_colors': {
        'warning': '#ff6b6b',
        'code': '#61afef',
        'info': '#98c379'
    }
}

FILE_EXTENSIONS = [
    '.py', '.js', '.lua', '.dll', '.exe', 
    '.jar', '.json', '.xml', '.cfg', '.ini'
]
