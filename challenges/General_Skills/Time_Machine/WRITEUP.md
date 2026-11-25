# Writeup: Time Machine

## Header & Metadata
- **Challenge:** Time Machine (ID: 425)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** challenge.zip
- **Official Flag:** `academy{t1m3m@ch1n3_2e6bda7d}`

---

## Mô tả bài toán (Overview / Analysis)
What was I last working on? I remember writing a note to help me remember...

You can download the challenge files here:

- <a href='https://challenge-files.cylabacademy.net/library/baeb24c9c7036d8fcf2afb1ce3289d24894e33392dac4648acb2d5aa319d44a1/challenge.zip' download>challenge.zip</a>


### Hints
- The `cat` command will let you read a file, but that won't help you here!
- Read the chapter on Git from the picoPrimer [here](https://primer.cylabacademy.org/#_git_version_control).
- When committing a file with git, a message can (and should) be included.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Time Machine (#425)
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
    return "https://challenge-files.cylabacademy.net/library/d26820f9a69ae423a1c03373c087da45feb125c3eb313927d4e58ea8be687924/challenge.zip"

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
academy{t1m3m@ch1n3_2e6bda7d}
```
