# Writeup: interencdec

## Header & Metadata
- **Challenge:** interencdec (ID: 418)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** enc_flag
- **Official Flag:** `academy{caesar_d3cr9pt3d_9948dfa2}`

---

## Mô tả bài toán (Overview / Analysis)
Can you get the real meaning from this file.

Download the file <a href='https://challenge-files.cylabacademy.net/library/b3f59d53f35ecfe9653969976a94f04fefc2a728e1974b51063c9db793731fcd/enc_flag' download>here</a>.


### Hints
- Engaging in various decoding processes is of utmost importance

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for interencdec (#418)
Category: Cryptography
Method: Multi-stage decoding (Base64 -> Base64 -> Caesar Cipher shift of 7)
"""
import base64
import re
from pathlib import Path

def solve():
    enc_flag_path = Path(__file__).resolve().parent / "enc_flag"
    with open(enc_flag_path, "r") as f:
        content = f.read().strip()

    print(f"[*] Raw input: {content}")

    # Stage 1: Base64 decode
    d1 = base64.b64decode(content).decode()
    print(f"[*] Stage 1 (Base64 decoded): {d1}")

    # Stage 2: Extract inner base64 string and decode
    inner_m = re.findall(r"['\"]([^'\"]+)['\"]", d1)
    inner = inner_m[0] if inner_m else d1
    d2 = base64.b64decode(inner).decode()
    print(f"[*] Stage 2 (Inner Base64 decoded): {d2}")

    # Stage 3: Caesar cipher decode (shift 7)
    shift = 7
    flag = ""
    for ch in d2:
        if 'a' <= ch <= 'z':
            flag += chr((ord(ch) - ord('a') - shift) % 26 + ord('a'))
        elif 'A' <= ch <= 'Z':
            flag += chr((ord(ch) - ord('A') - shift) % 26 + ord('A'))
        else:
            flag += ch

    print(f"[+] Decrypted Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{caesar_d3cr9pt3d_9948dfa2}
```
