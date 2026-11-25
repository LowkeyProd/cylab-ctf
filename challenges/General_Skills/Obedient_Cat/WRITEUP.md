# Writeup: Obedient Cat

## Header & Metadata
- **Challenge:** Obedient Cat (ID: 147)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** flag
- **Official Flag:** `academy{s4n1ty_v3r1f13d_61ddac22}`

---

## Mô tả bài toán (Overview / Analysis)
This file has a flag in plain sight (aka "in-the-clear").
<a href='https://challenge-files.cylabacademy.net/library/8a31150b13936d91fd7467e1a7c7f176ead316509772c06dbc6c95b3c44d7647/flag' download>flag</a>

### Hints
- Any hints about entering a command into the Terminal (such as the next one), will start with a '$'... everything after the dollar sign will be typed (or copy and pasted) into your Terminal.
- To get the file accessible in your shell, enter the following in the Terminal prompt: `$ wget ` and a link to the flag. The link can be copied from the details section.
- `$ man cat`

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Obedient Cat (#147)
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
    return "https://challenge-files.cylabacademy.net/library/8a31150b13936d91fd7467e1a7c7f176ead316509772c06dbc6c95b3c44d7647/flag"

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
academy{s4n1ty_v3r1f13d_61ddac22}
```
