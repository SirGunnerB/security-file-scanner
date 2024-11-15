# Detection Patterns

## Code Execution Patterns
| Pattern | Description | Risk Level |
|---------|-------------|------------|
| `eval()` | Dynamic code execution | High |
| `exec()` | Code execution | High |
| `subprocess` | Process execution | High |

## System Command Patterns
| Pattern | Description | Risk Level |
|---------|-------------|------------|
| `os.system()` | System command execution | High |
| `os.popen()` | Command with output | High |
| `os.spawn` | Process spawning | High |

## Network Patterns
| Pattern | Description | Risk Level |
|---------|-------------|------------|
| `socket.connect()` | Raw socket connection | Medium |
| `requests.get()` | HTTP request | Medium |
| `urllib` | URL operations | Medium |

## Encoding Patterns
| Pattern | Description | Risk Level |
|---------|-------------|------------|
| `base64` | Base64 encoding/decoding | Low |
| `encode()` | String encoding | Low |
| `crypto` | Cryptographic operations | Medium |
