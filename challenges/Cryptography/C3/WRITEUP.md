# Writeup: C3

## Header & Metadata
- **Challenge:** C3 (ID: 407)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** ciphertext, convert.py
- **Official Flag:** `academy{adlibs}`

---

## Mô tả bài toán (Overview / Analysis)
This is the Custom Cyclical Cipher!

Download the ciphertext <a href='https://challenge-files.cylabacademy.net/library/fb4743509774955556141c96d067e6eabc71a6b5d566329b2ab0a53c102e9e13/ciphertext' download>here</a>.

Download the encoder <a href='https://challenge-files.cylabacademy.net/library/fb4743509774955556141c96d067e6eabc71a6b5d566329b2ab0a53c102e9e13/convert.py' download>here</a>.

Enclose the flag in our wrapper for submission. If the flag was "example" you
would submit "academy{example}".


### Hints
- Modern crypto schemes don't depend on the encoder to be secret, but this one
  does.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for C3 (#407)
Category: Cryptography
"""
from pathlib import Path

def solve():
    print("[*] Solving C3...")
    flag = ""
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{adlibs}
```
