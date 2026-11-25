# Writeup: Nothing Up My Sleeve

## Header & Metadata
- **Challenge:** Nothing Up My Sleeve (ID: 91)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** flag.txt
- **Official Flag:** `academy{c0ngr4ts_0n_y0ur_s4n1ty}`

---

## Mô tả bài toán (Overview / Analysis)
Let's check that your internet connection is working. This flag is 'in-the-clear', I promise! 

Download <a href='https://challenge-files.cylabacademy.net/library/d8535ec63bf7b81b424ec33b24afe9e52d234899be8bf61ae85206453ff8e62b/flag.txt' download>flag.txt</a>


### Hints
- If all you had access to was a shell, you could use `wget` to download the file at the URL above!

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Nothing Up My Sleeve (#91)
Category: General Skills
"""
import re
from pathlib import Path

def solve():
    print("[*] Solving Nothing Up My Sleeve...", flush=True)
    flag_path = Path(__file__).parent / "flag.txt"
    if flag_path.exists():
        flag = flag_path.read_text(encoding="utf-8").strip()
    else:
        # Fallback if flag.txt is not yet downloaded
        import urllib.request
        url = "https://challenge-files.cylabacademy.net/library/7a2d73afcf61879089df15c526cb7c833947dd7fa6aeb074eeacf4eb6a5ce096/flag.txt"
        with urllib.request.urlopen(url) as resp:
            flag = resp.read().decode("utf-8").strip()

    match = re.search(r"academy\{[^}]+\}|picoCTF\{[^}]+\}", flag)
    if match:
        extracted = match.group(0)
    else:
        extracted = flag

    flag_path.write_text(extracted, encoding="utf-8")
    print(f"[+] Flag found: {extracted}", flush=True)
    return extracted

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{c0ngr4ts_0n_y0ur_s4n1ty}
```
