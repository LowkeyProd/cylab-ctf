# Writeup: Glory of the Garden

## Header & Metadata
- **Challenge:** Glory of the Garden (ID: 44)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** garden.jpg
- **Official Flag:** `academy{more_than_m33ts_the_3y36c4fc727}`

---

## Mô tả bài toán (Overview / Analysis)
This file contains more than it seems.
Get the flag from <a href='https://challenge-files.cylabacademy.net/library/0b84012e7d505751ee79c0407057962df7324463d7f8495cb79f5fb2dd998d7d/garden.jpg' download>garden.jpg</a>.

### Hints
- What is a hex editor?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity following writeup instructions.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Glory of the Garden (#44)
Category: Forensics
"""
import re
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return None

def solve():
    script_dir = Path(__file__).resolve().parent
    local_file = script_dir / "garden.jpg"
    
    data = None
    if local_file.exists():
        print(f"[*] Reading local challenge file: {local_file.name}")
        data = local_file.read_bytes()
    else:
        url = get_target_url()
        if url:
            print(f"[*] Downloading target from: {url}")
            r = requests.get(url, timeout=10)
            data = r.content
        else:
            print("[-] No local file or target URL found.")
            return None

    flag_pattern = re.compile(rb'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    m = flag_pattern.findall(data)
    if m:
        flag = m[0].decode('utf-8', errors='ignore')
        print(f"[+] Flag found: {flag}")
        (script_dir / "flag.txt").write_text(flag + "\n")
        return flag

    print("[-] Flag not found.")
    return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{more_than_m33ts_the_3y36c4fc727}
```
