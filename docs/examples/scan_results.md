# Example Scan Results

## Clean File Scan
```
[INFO] Scanning: clean_example.py
Files Scanned: 1
Issues Found: 0
Scan Time: 0.2s
No suspicious patterns detected
```

## Suspicious File Scan
```
[WARNING] Potential code execution found in suspicious_example.py:
eval('print("hello")')

[WARNING] System command execution found in suspicious_example.py:
os.system('dir')

[WARNING] Network activity found in suspicious_example.py:
socket.connect(('evil.com', 80))

Files Scanned: 1
Issues Found: 3
Scan Time: 0.3s
```

## Folder Scan
```
[INFO] Starting folder scan: /project/src
[WARNING] Network activity found in network.py:
requests.get('http://example.com')

[WARNING] Code execution found in utils.py:
eval(user_input)

[INFO] No issues found in config.py
[INFO] No issues found in helpers.py

Files Scanned: 4
Issues Found: 2
Scan Time: 1.2s
```
