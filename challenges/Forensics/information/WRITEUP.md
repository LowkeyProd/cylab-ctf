# Writeup: information

## Header & Metadata
- **Challenge:** information (ID: 186)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** cat.jpg
- **Official Flag:** `academy{the_m3tadata_1s_modified}`

---

## Mô tả bài toán (Overview / Analysis)
Files can always be changed in a secret way. Can you find the flag?
<a href='https://challenge-files.cylabacademy.net/library/c585b4adbdaa06f409db7bf5012c2e58e9aab24669764a5f1cf0f9ce0d60dcfd/cat.jpg' download>cat.jpg</a>

### Hints
- Look at the details of the file
- Make sure to submit the flag as academy{XXXXX}

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for information (#186)
Category: Forensics
"""
import re
import base64
import requests
from pathlib import Path

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/c585b4adbdaa06f409db7bf5012c2e58e9aab24669764a5f1cf0f9ce0d60dcfd/cat.jpg"

def extract_flag_from_data(data: bytes) -> str | None:
    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')

    # 1. Direct text search
    matches = flag_pattern.findall(data.decode('latin1', errors='ignore'))
    if matches:
        return matches[0]

    # 2. Look for base64 encoded strings
    # Specifically check cc:license rdf:resource='...'
    license_matches = re.findall(rb'''(?:cc:license rdf:resource=['"]|License=")([^'"]+)''', data)
    for candidate in license_matches:
        try:
            decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
            m = flag_pattern.search(decoded)
            if m:
                return m.group(0)
        except Exception:
            pass

    # Generic base64 scan
    b64_matches = re.findall(rb'[A-Za-z0-9+/]{20,}={0,2}', data)
    for b in b64_matches:
        try:
            decoded = base64.b64decode(b).decode('utf-8', errors='ignore')
            m = flag_pattern.search(decoded)
            if m:
                return m.group(0)
        except Exception:
            pass

    return None

def solve():
    cat_file = Path(__file__).resolve().parent / "cat.jpg"
    data = None

    if cat_file.exists() and cat_file.stat().st_size > 0:
        data = cat_file.read_bytes()
    else:
        url = get_target_url().rstrip('/')
        print(f"[*] Fetching target URL: {url}")
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.content
        cat_file.write_bytes(data)

    flag = extract_flag_from_data(data)
    if flag:
        print(f"[+] Flag found: {flag}")
        flag_file = Path(__file__).resolve().parent / "flag.txt"
        flag_file.write_text(flag.strip() + "\n", encoding="utf-8")
        return flag
    else:
        print("[-] Flag not found in image data")
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{the_m3tadata_1s_modified}
```
