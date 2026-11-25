# Writeup: DISKO 1

## Header & Metadata
- **Challenge:** DISKO 1 (ID: 505)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** disko-1.dd.gz
- **Official Flag:** `academy{1t5_ju5t_4_5tr1n9_19d7626c}`

---

## Mô tả bài toán (Overview / Analysis)
Can you find the flag in this disk image?

Download the disk image <a href='https://challenge-files.cylabacademy.net/library/ec407404f30c398e6779a1126e6d620b2c86b5f9e14afa720f70614a4e0a21bf/disko-1.dd.gz' download>here</a>.


### Hints
- Maybe Strings could help? If only there was a way to do that?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for DISKO 1 (#505)
Category: Forensics
"""
import gzip
import re
import urllib.request
from pathlib import Path

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("URL=") and len(line.split("=", 1)) > 1:
                val = line.split("=", 1)[1].strip()
                if val:
                    return val
    return "https://challenge-files.cylabacademy.net/library/0c9e001dbb48fbfe151ec242d8256abbfc0359446ea0e686c9c858359db19921/disko-1.dd.gz"

def solve():
    base_dir = Path(__file__).resolve().parent
    dd_file = base_dir / "disko-1.dd"
    gz_file = base_dir / "disko-1.dd.gz"
    flag_file = base_dir / "flag.txt"
    flag_pattern = re.compile(rb'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')

    data = None

    # 1. Try reading extracted dd image
    if dd_file.exists():
        print(f"[*] Reading disk image from {dd_file.name}...")
        data = dd_file.read_bytes()
    # 2. Try reading compressed gz file
    elif gz_file.exists():
        print(f"[*] Decompressing {gz_file.name}...")
        with gzip.open(gz_file, "rb") as f:
            data = f.read()
    # 3. Fallback to downloading using connection.cfg
    else:
        url = get_target_url()
        print(f"[*] Downloading disk image from {url}...")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            compressed = resp.read()
        try:
            data = gzip.decompress(compressed)
        except Exception:
            data = compressed

    matches = flag_pattern.findall(data)
    if matches:
        flag = matches[0].decode('utf-8', errors='ignore')
        print(f"[+] Flag found: {flag}")
        flag_file.write_text(flag.strip() + "\n", encoding='utf-8')
        return flag
    else:
        print("[-] Flag not found in image.")
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{1t5_ju5t_4_5tr1n9_19d7626c}
```
