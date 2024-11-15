# Security Pattern Detection

## ?? Detection Categories

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

## ?? Risk Levels

- **High**: Potentially dangerous operations that could harm the system
- **Medium**: Operations that might be legitimate but require attention
- **Low**: Common operations that rarely indicate malicious intent

## ?? Notes

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
