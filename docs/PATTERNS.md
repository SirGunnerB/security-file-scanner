# Security Pattern Detection Guide

## Overview

This guide documents security patterns detected by the scanner, their risk levels, and detection strategies.

## Risk Classification Matrix

| Risk Level | CVSS Score | Impact | Response Time |
|------------|------------|---------|---------------|
| Critical   | 9.0-10.0  | System compromise | Immediate |
| High       | 7.0-8.9   | Data exposure | Within 24h |
| Medium     | 4.0-6.9   | Limited impact | Within 72h |
| Low        | 0.1-3.9   | Minimal risk | Monitored |

## Detection Patterns

### 1. Code Execution Vectors 🔴

```python
# Critical Risk Patterns
CODE_EXEC_PATTERNS = {
    'eval': {
        'pattern': r'eval\s*\(',
        'risk': 'Critical',
        'mitigation': 'Use ast.literal_eval() for safe evaluation',
        'example': 'eval("print(\'hello\')")',
    },
    'exec': {
        'pattern': r'exec\s*\(',
        'risk': 'Critical',
        'mitigation': 'Avoid dynamic code execution',
        'example': 'exec("import os")',
    }
}
```

### 2. System Command Execution 🔴

```python
# High Risk Patterns
SYSTEM_CMD_PATTERNS = {
    'os.system': {
        'pattern': r'os\.system\s*\(',
        'risk': 'High',
        'mitigation': 'Use subprocess.run with shell=False',
        'example': 'os.system("rm file")',
    },
    'subprocess_shell': {
        'pattern': r'subprocess\..*shell\s*=\s*True',
        'risk': 'High',
        'mitigation': 'Avoid shell=True, use command lists',
        'example': 'subprocess.run(cmd, shell=True)',
    }
}
```

### 3. Network Operations 🟡

```python
# Medium Risk Patterns
NETWORK_PATTERNS = {
    'socket': {
        'pattern': r'socket\.connect\s*\(',
        'risk': 'Medium',
        'mitigation': 'Use application-layer protocols',
        'validation': r'^(localhost|127\.0\.0\.1)$',
    },
    'requests': {
        'pattern': r'requests\.(get|post|put|delete)',
        'risk': 'Medium',
        'mitigation': 'Validate URLs, use HTTPS',
        'validation': r'^https://',
    }
}
```

### 4. File Operations 🟡

```python
# Medium Risk Patterns
FILE_OP_PATTERNS = {
    'write': {
        'pattern': r'open\s*\([^)]+,\s*[\'"]w[\'"]\)',
        'risk': 'Medium',
        'mitigation': 'Validate paths, use safe directories',
        'validation': r'^[a-zA-Z0-9_\-./]+$',
    }
}
```

### 5. Data Encoding/Encryption 🟢

```python
# Low Risk Patterns
CRYPTO_PATTERNS = {
    'base64': {
        'pattern': r'base64\.(encode|decode)',
        'risk': 'Low',
        'audit': 'Check for sensitive data encoding',
    }
}
```

## Pattern Validation Rules

### 1. Path Validation
```regex
# Safe Path Pattern
^(?!.*\.\.|.*\/\.|.*\\\.)[a-zA-Z0-9_\-./\\]+$
```

### 2. URL Validation
```regex
# Safe URL Pattern
^https:\/\/(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/[^\s]*)?$
```

### 3. Command Validation
```regex
# Safe Command Pattern
^[a-zA-Z0-9_\-. ]+$
```

## Context-Aware Detection

### 1. Function Context
```python
def is_safe_context(code_block):
    """
    Check if pattern appears in safe context
    Example: test_eval() vs production_eval()
    """
    SAFE_CONTEXTS = [
        r'test_',
        r'mock_',
        r'dummy_'
    ]
```

### 2. Environment Context
```python
def check_environment():
    """
    Adjust risk levels based on environment
    """
    ENV_RISK_MODIFIERS = {
        'production': 1.5,  # Increase risk
        'testing': 0.5,    # Decrease risk
        'development': 0.3  # Minimal risk
    }
```

## False Positive Mitigation

### 1. Allowlist Patterns
```yaml
allowlist:
  - pattern: "eval(json.loads"
    reason: "Safe JSON parsing"
  - pattern: "subprocess.run(['git']"
    reason: "Standard git operations"
```

### 2. Context Exclusions
```yaml
exclude_contexts:
  - "*/tests/*"
  - "*/examples/*"
  - "*/vendor/*"
```

## Best Practices

1. **Pattern Updates**
   - Regular expression maintenance
   - Community feedback integration
   - Version control for patterns

2. **Scanning Strategy**
   ```python
   SCAN_STRATEGY = {
       'max_file_size': 1024 * 1024,  # 1MB
       'recursive_depth': 5,
       'follow_symlinks': False,
       'parallel_scans': True
   }
   ```

3. **Response Actions**
   ```python
   ACTIONS = {
       'Critical': lambda: notify_security_team(),
       'High': lambda: create_jira_ticket(),
       'Medium': lambda: log_finding(),
       'Low': lambda: update_metrics()
   }
   ```

## Limitations

1. **Detection Limitations**
   - Static analysis only
   - No runtime behavior analysis
   - Pattern bypass possibilities

2. **Performance Considerations**
   - Large file handling
   - Regular expression optimization
   - Memory constraints

## Updates and Maintenance

1. **Pattern Updates**
   ```bash
   # Update patterns
   ./update_patterns.sh
   
   # Verify patterns
   python -m pytest tests/patterns/
   ```

2. **Version Control**
   ```bash
   # Tag pattern updates
   git tag -a "patterns-v1.2.3" -m "Updated crypto patterns"
   ```

### 1. Code Execution Patterns
| Pattern | Description | Risk Level | Example |
|---------|-------------|------------|---------|
| `eval()` | Dynamic code execution | High | `eval("print('hello')")` |
| `exec()` | Code execution | High | `exec("import os")` |
| `subprocess` | Process execution | High | `subprocess.call(['ls'])` |
| `execfile()` | File execution | High | `execfile('script.py')` |
| `compile()` | Code compilation | Medium | `compile('code', 'string', 'exec')` |

### 2. System Command Patterns
| Pattern | Description | Risk Level | Example |
|---------|-------------|------------|---------|
| `os.system()` | Direct system commands | High | `os.system('rm file')` |
| `os.popen()` | Command with output | High | `os.popen('whoami')` |
| `os.spawn` | Process spawning | High | `os.spawnl(os.P_WAIT, 'cmd')` |
| `pty.spawn` | Terminal spawning | High | `pty.spawn('/bin/bash')` |
| `shell=True` | Shell execution | High | `subprocess.run(cmd, shell=True)` |

### 3. Network Activity
| Pattern | Description | Risk Level | Example |
|---------|-------------|------------|---------|
| `socket.connect()` | Raw connections | High | `socket.connect(('host', 80))` |
| `requests.post()` | HTTP requests | Medium | `requests.post('url', data)` |
| `urllib` | URL operations | Medium | `urllib.request.urlopen('url')` |
| `ftplib` | FTP operations | High | `FTP('ftp.server.com')` |
| `smtplib` | Email operations | Medium | `SMTP('smtp.server.com')` |

### 4. File Operations
| Pattern | Description | Risk Level | Example |
|---------|-------------|------------|---------|
| `open(mode='w')` | File writing | Medium | `open('file', 'w')` |
| `write()` | Data writing | Medium | `file.write(data)` |
| `chmod()` | Permission changes | High | `os.chmod('file', 0o777)` |
| `chown()` | Ownership changes | High | `os.chown('file', uid, gid)` |

### 5. Encoding/Encryption
| Pattern | Description | Risk Level | Example |
|---------|-------------|------------|---------|
| `base64` | Data encoding | Low | `base64.b64encode(data)` |
| `crypto` | Encryption ops | Medium | `Crypto.Cipher` |
| `hashlib` | Hashing ops | Low | `hashlib.md5()` |
| `secrets` | Random generation | Low | `secrets.token_hex()` |

### 6. Data Exfiltration
| Pattern | Description | Risk Level | Example |
|---------|-------------|------------|---------|
| `requests.post(data)` | Data upload | High | `requests.post(url, data)` |
| `ftp.stor` | FTP upload | High | `ftp.stor('file')` |
| `smtp.send` | Email sending | Medium | `smtp.send_message(msg)` |

### 7. System Information
| Pattern | Description | Risk Level | Example |
|---------|-------------|------------|---------|
| `platform` | OS info | Low | `platform.system()` |
| `os.uname` | System details | Low | `os.uname()` |
| `psutil` | System monitoring | Medium | `psutil.cpu_percent()` |

### 8. Registry Operations (Windows)
| Pattern | Description | Risk Level | Example |
|---------|-------------|------------|---------|
| `winreg` | Registry access | High | `winreg.OpenKey()` |
| `OpenKey` | Key operations | High | `OpenKey(HKEY_LOCAL_MACHINE)` |
| `RegSetValue` | Value changes | High | `RegSetValue(key, 'name')` |

### 9. Browser/User Data
| Pattern | Description | Risk Level | Example |
|---------|-------------|------------|---------|
| `selenium` | Browser control | Medium | `webdriver.Chrome()` |
| `cookielib` | Cookie access | Medium | `cookielib.CookieJar()` |
| `keylogger` | Keystroke logging | High | `keyboard.on_press()` |

## Risk Levels
- **High**: Potentially dangerous operations that could harm the system
- **Medium**: Operations that might be legitimate but require attention
- **Low**: Common operations that rarely indicate malicious intent

## Notes
1. False Positives:
   - Some patterns may be legitimate in certain contexts
   - Always verify findings manually
   - Consider the application's purpose

2. Best Practices:
   - Regular pattern updates
   - Context-aware scanning
   - Multiple verification methods

3. Limitations:
   - Pattern-based detection only
   - No behavioral analysis
   - No runtime monitoring
