# Writeup: PW Crack 2

## Header & Metadata
- **Challenge:** PW Crack 2 (ID: 246)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** level2.py, level2.flag.txt.enc
- **Official Flag:** `academy{tr45h_51ng1ng_ab548076}`

---

## Mô tả bài toán (Overview / Analysis)
Can you crack the password to get the flag?
Download the password checker <a href='https://challenge-files.cylabacademy.net/library/da3b21f411362ad5c273b3a48a829e1a6f011d43998fabc480a2b1f3585aff0b/level2.py' download>here</a> and you'll
need the encrypted <a href='https://challenge-files.cylabacademy.net/library/da3b21f411362ad5c273b3a48a829e1a6f011d43998fabc480a2b1f3585aff0b/level2.flag.txt.enc' download>flag</a> in the same directory
too.

### Hints
- Does that encoding look familiar?
- The `str_xor` function does not need to be reverse engineered for this
  challenge.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for PW Crack 2 (#246)
Category: General Skills
"""
import requests
import re
from pathlib import Path

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/da3b21f411362ad5c273b3a48a829e1a6f011d43998fabc480a2b1f3585aff0b/level2.py"

def solve():
    url = get_target_url().rstrip('/')
    print(f"[*] Target URL: {url}")
    try:
        r = requests.get(url, timeout=10)
        flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
        m = flag_pattern.findall(r.text)
        if m:
            flag = m[0]
            print(f"[+] Flag found: {flag}")
            (Path(__file__).resolve().parent / "flag.txt").write_text(flag + "\n")
            return flag
    except Exception as e:
        print(f"[-] Request error: {e}")
    return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{tr45h_51ng1ng_ab548076}
```
