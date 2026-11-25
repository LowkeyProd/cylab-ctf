# Writeup: EVEN RSA CAN BE BROKEN???

## Header & Metadata
- **Challenge:** EVEN RSA CAN BE BROKEN??? (ID: 470)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `nc chatelaine.cylabacademy.net 48559`
- **Attached Files:** encrypt.py
- **Official Flag:** `academy{tw0_1$_pr!m3207f407f}`

---

## Mô tả bài toán (Overview / Analysis)
This service provides you an encrypted flag. Can you decrypt it with just N & e?
Connect to the program with netcat:

`$ nc chatelaine.cylabacademy.net 48559`

The program's source code can be downloaded <a href='https://challenge-files.cylabacademy.net/library/548e8da21a43607b2b9c2bf9c7c374828e84cfd56fb38a24958eb8963afa09f1/encrypt.py' download>here</a>.

### Hints
- How much do we trust randomness?
- Notice anything interesting about N?
- Try comparing N across multiple requests

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Fast Heuristics.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for EVEN RSA CAN BE BROKEN??? (#470)
Category: Cryptography
Target: chatelaine.cylabacademy.net:45446
Vulnerability: The RSA modulus N is even, meaning one of the prime factors is p = 2!
"""
import re
from pwn import *
from Crypto.Util.number import inverse, long_to_bytes

HOST = "chatelaine.cylabacademy.net"
PORT = 48559

def solve():
    io = remote(HOST, PORT)
    data = io.recvall(timeout=10).decode()
    io.close()

    n_match = re.search(r'N:\s*(\d+)', data)
    e_match = re.search(r'e:\s*(\d+)', data)
    c_match = re.search(r'cyphertext:\s*(\d+)', data)

    if not (n_match and e_match and c_match):
        print("[-] Failed to parse N, e, cyphertext")
        return None

    N = int(n_match.group(1))
    e = int(e_match.group(1))
    c = int(c_match.group(1))

    print(f"[+] Retrieved N: {N}")
    print(f"[+] Retrieved e: {e}")
    print(f"[+] Retrieved c: {c}")

    # Check if N is even (p = 2)
    if N % 2 == 0:
        p = 2
        q = N // p
        phi = (p - 1) * (q - 1)
        d = inverse(e, phi)
        m = pow(c, d, N)
        flag = long_to_bytes(m).decode(errors="ignore")
        print(f"[+] Decrypted Flag: {flag}")
        return flag
    else:
        print("[-] N is not even, checking small factors...")
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{tw0_1$_pr!m3207f407f}
```
