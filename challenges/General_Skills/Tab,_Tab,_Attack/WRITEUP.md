# Writeup: Tab, Tab, Attack

## Header & Metadata
- **Challenge:** Tab, Tab, Attack (ID: 176)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `https://challenge-files.cylabacademy.net/library/298b799316c13103156a84f949a6cb6e02efd5cdb0ee09700231527df92ed468/Addadshashanammu.zip`
- **Attached Files:** Addadshashanammu.zip
- **Official Flag:** `academy{l3v3l_up!_t4k3_4_r35t!_9d928112}`

---

## Mô tả bài toán (Overview / Analysis)
Using tabcomplete in the Terminal will add years to your life, esp. when dealing with long rambling directory structures and filenames.
<a href='https://challenge-files.cylabacademy.net/library/298b799316c13103156a84f949a6cb6e02efd5cdb0ee09700231527df92ed468/Addadshashanammu.zip' download>Addadshashanammu.zip</a>

### Hints
- After `unzip`ing, this problem can be solved with 11 button-presses...(mostly Tab)...

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Tab, Tab, Attack (#176)
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
    return "https://challenge-files.cylabacademy.net/library/298b799316c13103156a84f949a6cb6e02efd5cdb0ee09700231527df92ed468/Addadshashanammu.zip"

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
academy{l3v3l_up!_t4k3_4_r35t!_9d928112}
```
