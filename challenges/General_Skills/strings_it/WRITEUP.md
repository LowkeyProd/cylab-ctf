# Writeup: strings it

## Header & Metadata
- **Challenge:** strings it (ID: 37)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `https://challenge-files.cylabacademy.net/library/dede17d717e026b75f6b9e7fb2c1601b46093ced6f209b8f6b27ffd883a9ae2f/strings`
- **Attached Files:** strings
- **Official Flag:** `academy{5tRIng5_1T_b1e21039}`

---

## Mô tả bài toán (Overview / Analysis)

Can you find the flag in <a href='https://challenge-files.cylabacademy.net/library/dede17d717e026b75f6b9e7fb2c1601b46093ced6f209b8f6b27ffd883a9ae2f/strings' download>file</a> without running it?

### Hints
- [strings](https://linux.die.net/man/1/strings)

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for strings it (#37)
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
    return "https://challenge-files.cylabacademy.net/library/dede17d717e026b75f6b9e7fb2c1601b46093ced6f209b8f6b27ffd883a9ae2f/strings"

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
academy{5tRIng5_1T_b1e21039}
```
