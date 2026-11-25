# Writeup: First Grep

## Header & Metadata
- **Challenge:** First Grep (ID: 85)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** file
- **Official Flag:** `academy{grep_is_good_to_find_things_b9De1cAb}`

---

## Mô tả bài toán (Overview / Analysis)
Can you find the flag in the file? This would be really tedious to look through manually, something tells me there is a better way.
The flag is in this <a href='https://challenge-files.cylabacademy.net/library/92db87573ed8c5d7bb720cbe14f6884c1295c16b5bf6b8fee9725cae249551aa/file' download>file</a>.

### Hints
- grep [tutorial](https://ryanstutorials.net/linuxtutorial/grep.php)

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for First Grep (#85)
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
    return "https://challenge-files.cylabacademy.net/library/3ff907ca5b2c4bf9b5c47914ad89787b1dcbf5e88d99b96c52eb652a6b5f3729/file"

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
academy{grep_is_good_to_find_things_b9De1cAb}
```
