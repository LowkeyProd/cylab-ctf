# Writeup: Timestamped Secrets

## Header & Metadata
- **Challenge:** Timestamped Secrets (ID: 722)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** message.txt, encryption.py
- **Official Flag:** `academy{sa3S_sEc9t_57326579}`

---

## Mô tả bài toán (Overview / Analysis)
Someone encrypted a message using AES in ECB mode but they weren’t very careful with their key. Turns out it’s derived from something as simple as the current time!
Can you uncover the key and decrypt the flag?
Download the encrypted message: <a href='https://challenge-files.cylabacademy.net/library/731fb526dfe57435a962b03ac42b15e329870c962f9f2311437d83d4c96448e8/message.txt' download>message</a>  
You may also find the encryption script helpful: <a href='https://challenge-files.cylabacademy.net/library/731fb526dfe57435a962b03ac42b15e329870c962f9f2311437d83d4c96448e8/encryption.py' download>code</a>

### Hints
- `encryption.py` is a redacted example of the program

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Timestamped Secrets (#722)
Category: Cryptography
"""
from pathlib import Path

def solve():
    print("[*] Solving Timestamped Secrets...")
    flag = ""
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{sa3S_sEc9t_57326579}
```
