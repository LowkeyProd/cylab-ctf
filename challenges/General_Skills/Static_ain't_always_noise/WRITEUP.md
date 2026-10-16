# Writeup: Static ain't always noise

## Header & Metadata
- **Challenge:** Static ain't always noise (ID: 163)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `https://challenge-files.cylabacademy.net/library/fbc420391fe28e2adcd05096604decb354d8ada0a715fc63dff030026865407b/static`
- **Attached Files:** static, ltdis.sh
- **Official Flag:** `academy{d15a5m_t34s3r_fac3431a}`

---

## Mô tả bài toán (Overview / Analysis)
Can you look at the data in this binary? The bash script might help!
<a href='https://challenge-files.cylabacademy.net/library/fbc420391fe28e2adcd05096604decb354d8ada0a715fc63dff030026865407b/static' download>static</a>, <a href='https://challenge-files.cylabacademy.net/library/fbc420391fe28e2adcd05096604decb354d8ada0a715fc63dff030026865407b/ltdis.sh' download>ltdis.sh</a>

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Static ain't always noise (#163)
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
    return "https://challenge-files.cylabacademy.net/library/fbc420391fe28e2adcd05096604decb354d8ada0a715fc63dff030026865407b/static"

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
academy{d15a5m_t34s3r_fac3431a}
```
