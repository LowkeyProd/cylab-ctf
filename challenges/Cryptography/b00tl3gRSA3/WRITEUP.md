# Writeup: b00tl3gRSA3

## Header & Metadata
- **Challenge:** b00tl3gRSA3 (ID: 78)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `nc xebec.cylabacademy.net 26796`
- **Attached Files:** None
- **Official Flag:** `academy{too_many_fact0rs_0164780}`

---

## Mô tả bài toán (Overview / Analysis)
Why use p and q when I can use more?
Connect with `nc xebec.cylabacademy.net 26796`.

### Hints
- There's more prime factors than p and q, finding d is going to be different.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for b00tl3gRSA3 (#78)
Target: chatelaine.cylabacademy.net:28505
"""
import socket
import math
import random
import re
import sys
from pathlib import Path
from Crypto.Util.number import long_to_bytes
import sympy

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 28505
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("HOST="xebec.cylabacademy.net"
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def pollard_rho(n):
    if n % 2 == 0:
        return 2
    if n % 3 == 0:
        return 3
    x = random.randint(2, n - 1)
    y = x
    c = random.randint(1, n - 1)
    d = 1
    f = lambda v: (v * v + c) % n
    while d == 1:
        x = f(x)
        y = f(f(y))
        d = math.gcd(abs(x - y), n)
        if d == n:
            return pollard_rho(n)
    return d

def factor_all(n):
    cur = n
    factors = []
    while cur > 1:
        if sympy.isprime(cur):
            factors.append(cur)
            break
        d = pollard_rho(cur)
        while not sympy.isprime(d):
            d = pollard_rho(d)
        factors.append(d)
        cur //= d
        print(f"[*] Found factor {d}, remaining bits: {cur.bit_length()}", flush=True)
    return factors

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.settimeout(5.0)

    data = b""
    while True:
        try:
            buf = s.recv(4096)
            if not buf:
                break
            data += buf
        except socket.timeout:
            break
    s.close()

    text = data.decode(errors="ignore")
    print("[*] Received server data:", flush=True)
    print(text, flush=True)

    c_match = re.search(r"c:\s*(\d+)", text)
    n_match = re.search(r"n:\s*(\d+)", text)
    e_match = re.search(r"e:\s*(\d+)", text)

    if not (c_match and n_match and e_match):
        print("[-] Failed to parse RSA parameters!", flush=True)
        sys.exit(1)

    c = int(c_match.group(1))
    n = int(n_match.group(1))
    e = int(e_match.group(1))

    print(f"[*] n bit length: {n.bit_length()}", flush=True)
    print("[*] Factoring n with Pollard's rho...", flush=True)
    factors = factor_all(n)
    print(f"[*] Total prime factors: {len(factors)}", flush=True)

    phi = 1
    for p in factors:
        phi *= (p - 1)

    d = pow(e, -1, phi)
    m = pow(c, d, n)
    flag_bytes = long_to_bytes(m)
    print(f"[*] Decrypted bytes: {flag_bytes}", flush=True)

    flag_match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", flag_bytes.decode(errors="ignore"))
    if flag_match:
        flag = flag_match.group(1)
        print(f"[+] Flag found: {flag}", flush=True)
        Path("flag.txt").write_text(flag)
        print("[+] Flag saved to flag.txt", flush=True)
    else:
        print("[-] Flag not found in decrypted plaintext", flush=True)
        sys.exit(1)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{too_many_fact0rs_0164780}
```
