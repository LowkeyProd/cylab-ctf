# Writeup: CanYouSee

## Header & Metadata
- **Challenge:** CanYouSee (ID: 408)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** unknown.zip
- **Official Flag:** `academy{ME74D47A_HIDD3N_9266de1e}`

---

## Mô tả bài toán (Overview / Analysis)
How about some hide and seek?

Download this file <a href='https://challenge-files.cylabacademy.net/library/3781b74e6ee2cd04bb03da6614e1c184422f725bf14a19d5b61f8b2038e1c11c/unknown.zip' download>here</a>.


### Hints
- How can you view the information about the picture?
- If something isn't in the expected form, maybe it deserves attention?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for CanYouSee (#408)
Category: Forensics | Difficulty: Easy
"""
import sys
import os
import re
import base64
import zipfile
from pathlib import Path
import requests

def get_config():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def extract_flag_from_data(data: bytes):
    # Check for direct plaintext flag
    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    text_matches = flag_pattern.findall(data.decode('utf-8', errors='ignore'))
    if text_matches:
        return text_matches[0]

    # Check for base64 encoded strings
    for match in re.finditer(rb'[A-Za-z0-9+/]{16,}={0,2}', data):
        token = match.group(0)
        try:
            decoded = base64.b64decode(token).decode('utf-8', errors='ignore')
            m = flag_pattern.search(decoded)
            if m:
                return m.group(0)
        except Exception:
            continue
    return None

def solve():
    base_dir = Path(__file__).resolve().parent
    img_path = base_dir / "ukn_reality.jpg"
    zip_path = base_dir / "unknown.zip"
    config = get_config()
    url = config.get("URL")

    # If image does not exist, look for zip or download it
    if not img_path.exists():
        if not zip_path.exists() and url:
            print(f"[*] Downloading archive from {url}...")
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            zip_path.write_bytes(resp.content)

        if zip_path.exists():
            print(f"[*] Extracting {zip_path.name}...")
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(base_dir)

    if not img_path.exists():
        print(f"[-] Image file {img_path} not found!")
        return None

    data = img_path.read_bytes()
    flag = extract_flag_from_data(data)

    if flag:
        print(f"[+] Flag found: {flag}")
        flag_file = base_dir / "flag.txt"
        flag_file.write_text(flag + "\n", encoding="utf-8")
        return flag
    else:
        print("[-] Flag not found in image data.")
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{ME74D47A_HIDD3N_9266de1e}
```
