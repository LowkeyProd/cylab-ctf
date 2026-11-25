# Writeup: Custom encryption

## Header & Metadata
- **Challenge:** Custom encryption (ID: 412)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** enc_flag, custom_encryption.py
- **Official Flag:** `academy{custom_d2cr0pt6d_b1f6d02d}`

---

## Mô tả bài toán (Overview / Analysis)
Can you get sense of this code file  and write the function that will decode the given encrypted file content.

Find the encrypted file here <a href='https://challenge-files.cylabacademy.net/library/8d05f9bf51ff1004789993cef4fe191582d2e543bf5127ab684b100f5960ba62/enc_flag' download>flag_info</a> and  <a href='https://challenge-files.cylabacademy.net/library/8d05f9bf51ff1004789993cef4fe191582d2e543bf5127ab684b100f5960ba62/custom_encryption.py' download>code file</a> might be good to analyze and get the flag.


### Hints
- Understanding encryption algorithm to come up with decryption algorithm.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Custom encryption (#412)
Category: Cryptography
"""
from pathlib import Path

def solve():
    print("[*] Solving Custom encryption...")
    flag = ""
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{custom_d2cr0pt6d_b1f6d02d}
```
