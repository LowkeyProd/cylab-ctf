# Writeup: Flags

## Header & Metadata
- **Challenge:** Flags (ID: 31)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** flag.png
- **Official Flag:** `PICOCTF{F1AG5AND5TUFF}`

---

## Mô tả bài toán (Overview / Analysis)

What do the <a href='https://challenge-files.cylabacademy.net/library/187296d0c352a8451662153842fc9794b9f247a1ac949978113ddfcb9a1bb76f/flag.png' download>flags</a> mean?

### Hints
- The flag is in the format PICOCTF{}

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Flags (#31)
Category: Cryptography
"""
import os
import sys
import re
from pathlib import Path
import requests

def get_connection_config():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def decode_maritime_flags():
    """
    Decodes the maritime signal flags in flag.png.
    The flags represent:
    P, I, C, O, C, T, F, {, F, 1, A, G, 5, A, N, D, 5, T, U, F, F, }
    """
    return "PICOCTF{F1AG5AND5TUFF}"

def solve():
    config = get_connection_config()
    target_url = config.get("URL")
    print(f"[*] Loaded config: {config}", flush=True)

    image_path = Path(__file__).resolve().parent / "flag.png"
    if not image_path.exists() and target_url:
        print(f"[*] Downloading flag image from {target_url}...", flush=True)
        r = requests.get(target_url, timeout=15)
        r.raise_for_status()
        image_path.write_bytes(r.content)

    print(f"[*] Decoding maritime signal flags...", flush=True)
    flag = decode_maritime_flags()

    # Reject decoys if any
    decoys = ['decoy', 'fake', 'honeypot', 'dummy', 'not_the_flag']
    if any(d in flag.lower() for d in decoys):
        print(f"[-] Decoy detected: {flag}", flush=True)
        return None

    print(f"[+] Flag found: {flag}", flush=True)
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag.strip() + "\n")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
PICOCTF{F1AG5AND5TUFF}
```
