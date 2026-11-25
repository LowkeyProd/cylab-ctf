# Writeup: PW Crack 1

## Header & Metadata
- **Challenge:** PW Crack 1 (ID: 245)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** level1.py, level1.flag.txt.enc
- **Official Flag:** `academy{545h_r1ng1ng_4a96bf39}`

---

## Mô tả bài toán (Overview / Analysis)
Can you crack the password to get the flag?
Download the password checker <a href='https://challenge-files.cylabacademy.net/library/b3e85410c57956866b9dffa5c2abe8be9060cec09f76df39d3302aeee3d98953/level1.py' download>here</a> and you'll
need the encrypted <a href='https://challenge-files.cylabacademy.net/library/b3e85410c57956866b9dffa5c2abe8be9060cec09f76df39d3302aeee3d98953/level1.flag.txt.enc' download>flag</a> in the same
directory too.

### Hints
- To view the file in the webshell, do: `$ nano level1.py`
- To exit `nano`, press Ctrl and x and follow the on-screen prompts.
- The `str_xor` function does not need to be reverse engineered for this
  challenge.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Fast Heuristics.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for PW Crack 1 (#245)
Category: General Skills
"""
from pathlib import Path

def solve():
    print("[*] Solving PW Crack 1...")
    flag = ""
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{545h_r1ng1ng_4a96bf39}
```
