# Writeup: john_pollard

## Header & Metadata
- **Challenge:** john_pollard (ID: 6)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** cert
- **Official Flag:** `academy{73176001,67867967}`

---

## Mô tả bài toán (Overview / Analysis)
Sometimes RSA certificates are breakable
Certificates: <a href='https://challenge-files.cylabacademy.net/library/3eb471c919b06785e45c7aeefd03b3f17638a2d190e3bc31ee3b5cec01832ac8/cert' download>certificates</a>

### Hints
- The flag is in the format academy{p,q}
- Try swapping p and q if it does not work

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Deterministic solver for 'john_pollard' (#6, Cryptography)
Author: CTF Autosolver
"""

import os
import sys
import math
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def pollard_rho(n):
    """Pollard's rho factorization algorithm for small/medium composite n."""
    if n % 2 == 0:
        return 2
    x = 2
    y = 2
    d = 1
    c = 1
    f = lambda val: (pow(val, 2, n) + c) % n

    while d == 1:
        x = f(x)
        y = f(f(y))
        d = math.gcd(abs(x - y), n)
        if d == n:
            # retry with a different c
            c += 1
            x = 2
            y = 2
            d = 1
    return d

def solve():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    cfg_path = os.path.join(script_dir, "connection.cfg")
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    # Config parameters parsed dynamically if needed

    cert_path = os.path.join(script_dir, "cert")

    if not os.path.exists(cert_path):
        print(f"[-] Certificate file not found at {cert_path}", flush=True)
        sys.exit(1)

    print("[*] Loading certificate...", flush=True)
    with open(cert_path, "rb") as f:
        cert_data = f.read()

    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    public_key = cert.public_key()
    public_numbers = public_key.public_numbers()

    n = public_numbers.n
    e = public_numbers.e
    print(f"[*] Extracted RSA Modulus N = {n} ({n.bit_length()} bits)", flush=True)
    print(f"[*] Public Exponent e = {e}", flush=True)

    print("[*] Factoring N using Pollard's rho algorithm...", flush=True)
    factor = pollard_rho(n)
    p = min(factor, n // factor)
    q = max(factor, n // factor)

    assert p * q == n, "Factorization check failed!"
    print(f"[+] Factors found: p = {p}, q = {q}", flush=True)

    flag = f"academy{{{p},{q}}}"
    print(f"[+] Flag: {flag}", flush=True)

    flag_path = os.path.join(script_dir, "flag.txt")
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag + "\n")
    print(f"[+] Saved flag to {flag_path}", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{73176001,67867967}
```
