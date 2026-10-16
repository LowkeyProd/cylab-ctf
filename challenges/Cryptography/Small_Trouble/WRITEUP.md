# Writeup: Small Trouble

## Header & Metadata
- **Challenge:** Small Trouble (ID: 718)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `https://challenge-files.cylabacademy.net/library/f38c357a8331785ca63ae8e6e36d20e6f8160839a03dc3bdb28e6dcaee33e15f/message.txt`
- **Attached Files:** message.txt, encryption.py
- **Official Flag:** `academy{sm4ll_d_c0409804}`

---

## Mô tả bài toán (Overview / Analysis)
Everything seems secure; strong numbers, familiar parameters but something small might ruin it all. Can you recover the message?
Download the <a href='https://challenge-files.cylabacademy.net/library/f38c357a8331785ca63ae8e6e36d20e6f8160839a03dc3bdb28e6dcaee33e15f/message.txt' download>message</a>. And source <a href='https://challenge-files.cylabacademy.net/library/f38c357a8331785ca63ae8e6e36d20e6f8160839a03dc3bdb28e6dcaee33e15f/encryption.py' download>code</a>

### Hints
- This might be a job for Boneh-Durfee.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Small Trouble (ID: 718) - CyLab CTF
Category: Cryptography
Vulnerability: RSA Small Private Exponent (Wiener's Attack)
"""
import os
import sys
from Crypto.Util.number import long_to_bytes

def continued_fraction(e, n):
    cf = []
    while n != 0:
        q = e // n
        cf.append(q)
        e, n = n, e - q * n
    return cf

def convergents(cf):
    conv = []
    n0, n1 = 0, 1
    d0, d1 = 1, 0
    for q in cf:
        n2 = q * n1 + n0
        d2 = q * d1 + d0
        conv.append((n2, d2))
        n0, n1 = n1, n2
        d0, d1 = d1, d2
    return conv

def solve():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    message_path = os.path.join(script_dir, "message.txt")
    
    with open(message_path, "r") as f:
        lines = f.read().splitlines()
        n = int(lines[0].split("=")[1].strip())
        e = int(lines[1].split("=")[1].strip())
        c = int(lines[2].split("=")[1].strip())

    cf = continued_fraction(e, n)
    convs = convergents(cf)

    flag = None
    for k, d in convs:
        if k == 0 or d == 0:
            continue
        m = pow(c, d, n)
        try:
            b = long_to_bytes(m)
            if b"academy{" in b or b"picoCTF{" in b:
                flag = b.decode()
                break
        except Exception:
            continue

    if flag:
        print(f"[+] Flag found: {flag}")
        flag_path = os.path.join(script_dir, "flag.txt")
        with open(flag_path, "w") as f:
            f.write(flag + "\n")
        print(f"[+] Saved flag to {flag_path}")
        return flag
    else:
        print("[-] Flag not found")
        sys.exit(1)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{sm4ll_d_c0409804}
```
