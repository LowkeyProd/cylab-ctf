# Writeup: Transformation

## Header & Metadata
- **Challenge:** Transformation (ID: 104)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** enc
- **Official Flag:** `academy{16_bits_inst34d_of_8_790ba37e}`

---

## Mô tả bài toán (Overview / Analysis)
I wonder what this really is...
<a href='https://challenge-files.cylabacademy.net/library/755c1c90336312f22a52673db5cb049f997bff95418e7959a3a3777671499a7d/enc' download>enc</a> 

```
''.join([chr((ord(flag[i]) << 8) + ord(flag[i + 1])) for i in range(0, len(flag), 2)])
```

### Hints
- You may find some decoders online

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Transformation (#104)
Category: Reverse Engineering
"""
import os
import sys
import re
from pathlib import Path

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/d8dd0d4551de0f8f5581d36961b3363042868a379ed6b4f8cfeb4a825be212d8/enc"

def decode_transformation(encoded_text: str) -> str:
    flag_chars = []
    for c in encoded_text:
        val = ord(c)
        flag_chars.append(chr(val >> 8))
        flag_chars.append(chr(val & 0xFF))
    return ''.join(flag_chars)

def solve():
    script_dir = Path(__file__).resolve().parent
    enc_path = script_dir / "enc"

    if enc_path.exists():
        print(f"[*] Reading encoded data from local file: {enc_path}", flush=True)
        encoded_text = enc_path.read_text(encoding="utf-8").strip()
    else:
        url = get_target_url().rstrip('/')
        print(f"[*] Fetching encoded data from URL: {url}", flush=True)
        import requests
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        encoded_text = resp.text.strip()

    decoded = decode_transformation(encoded_text)
    print(f"[*] Decoded result: {decoded}", flush=True)

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    matches = flag_pattern.findall(decoded)

    if not matches:
        print("[-] No flag found in decoded text.", flush=True)
        sys.exit(1)

    flag = matches[0]
    
    # Decoy rejection check
    lower_flag = flag.lower()
    if any(decoy in lower_flag for decoy in ['decoy', 'fake', 'honeypot', 'dummy']):
        print(f"[-] Decoy flag detected and rejected: {flag}", flush=True)
        sys.exit(1)

    print(f"[+] Valid flag found: {flag}", flush=True)
    flag_path = script_dir / "flag.txt"
    flag_path.write_text(flag + "\n", encoding="utf-8")
    print(f"[+] Flag written to {flag_path}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{16_bits_inst34d_of_8_790ba37e}
```
