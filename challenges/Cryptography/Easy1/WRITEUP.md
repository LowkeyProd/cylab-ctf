# Writeup: Easy1

## Header & Metadata
- **Challenge:** Easy1 (ID: 43)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** table.txt
- **Official Flag:** `academy{CRYPTOISFUN}`

---

## Mô tả bài toán (Overview / Analysis)
The one time pad can be cryptographically secure, but not when you know the key. Can you solve this?
We've given you the encrypted flag, key, and a table to help `UFJKXQZQUNB` with the key of `SOLVECRYPTO`. Can you use this <a href='https://challenge-files.cylabacademy.net/library/14a944b4b00c6d6e9213b62098e0c8a8d77219757b1a51d9af4bc15e263b6b92/table.txt' download>table</a> to solve it?.

### Hints
- Submit your answer in our flag format. For example, if your answer was 'hello', you would submit 'academy{HELLO}' as the flag.
- Please use all caps for the message.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Easy1 (#43)
Category: Cryptography
"""
import sys
from pathlib import Path

def parse_connection_cfg():
    cfg = {}
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg

def decrypt_vigenere(ciphertext: str, key: str) -> str:
    plaintext = []
    for c, k in zip(ciphertext, key):
        c_val = ord(c) - ord('A')
        k_val = ord(k) - ord('A')
        p_val = (c_val - k_val) % 26
        plaintext.append(chr(p_val + ord('A')))
    return "".join(plaintext)

def solve():
    cfg = parse_connection_cfg()
    print(f"[*] Loaded config: {cfg}", flush=True)

    ciphertext = "UFJKXQZQUNB"
    key = "SOLVECRYPTO"

    decrypted = decrypt_vigenere(ciphertext, key)
    print(f"[+] Decrypted text: {decrypted}", flush=True)

    flag = f"academy{{{decrypted}}}"
    print(f"[+] Flag: {flag}", flush=True)

    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Flag successfully saved to {flag_file}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{CRYPTOISFUN}
```
