# Writeup: fixme1.py

## Header & Metadata
- **Challenge:** fixme1.py (ID: 240)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** fixme1.py
- **Official Flag:** `academy{1nd3nt1ty_cr1515_69b5da78}`

---

## Mô tả bài toán (Overview / Analysis)
Fix the syntax error in this Python script to print the flag.
<a href='https://challenge-files.cylabacademy.net/library/1565d4e65ddf11dca51a32c7e3454af6c674f43ea941ba6fba02477511e70581/fixme1.py' download>Download Python script</a>

### Hints
- Indentation is very meaningful in Python
- To view the file in the webshell, do: `$ nano fixme1.py`
- To exit `nano`, press Ctrl and x and follow the on-screen prompts.
- The `str_xor` function does not need to be reverse engineered for this
  challenge.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity following writeup instructions.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for fixme1.py (#240)
Category: General Skills
"""
import subprocess
import re
from pathlib import Path

def solve():
    print("[*] Solving fixme1.py...", flush=True)
    res = subprocess.run(["python", "fixme1.py"], capture_output=True, text=True, check=True)
    out = res.stdout
    print(out, flush=True)
    
    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", out)
    if not match:
        raise ValueError("Flag pattern not found in output")
    
    flag = match.group(1)
    Path("flag.txt").write_text(flag, encoding="utf-8")
    print(f"[+] Flag found: {flag}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{1nd3nt1ty_cr1515_69b5da78}
```
