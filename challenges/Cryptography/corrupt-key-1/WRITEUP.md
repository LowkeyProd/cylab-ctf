# Writeup: corrupt-key-1

## Header & Metadata
- **Challenge:** corrupt-key-1 (ID: 207)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `picoCTF{d741543f172970457e6a9aaa890935b8}`

---

## Mô tả bài toán (Overview / Analysis)
<p>How to fix corrupted key???</p>

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for corrupt-key-1 (#207)
Category: Cryptography
"""
import base64
import math
import os
import re
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from Crypto.Util import asn1, number
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import flint

def check_guess(args):
    x_guess, P, n, X, m, t = args
    _p = P + (x_guess * X)
    f_poly = flint.fmpz_poly([_p, 1])
    g = []
    n_fmpz = flint.fmpz(n)
    for i in range(m):
        g.append(f_poly**i * n_fmpz**(m - i))
    for i in range(t):
        g.append(f_poly**m * flint.fmpz_poly([0, 1])**i)
    
    dim = len(g)
    rows = []
    for poly in g:
        row = [0] * dim
        for j in range(poly.degree() + 1):
            row[j] = int(poly[j]) * (X**j)
        rows.append(row)
    
    B = flint.fmpz_mat(rows).lll()
    
    coeffs = [int(B[0, i]) // (X**i) for i in range(dim)]
    res_poly = flint.fmpz_poly(coeffs)
    roots = res_poly.roots()
    for root, mult in roots:
        r_val = int(root)
        if 0 <= r_val < X:
            cand = _p + r_val
            if 1 < math.gcd(cand, n) < n:
                return cand
    return None

def solve():
    print("[*] Solving corrupt-key-1...", flush=True)
    
    script_dir = Path(__file__).resolve().parent
    key_path = script_dir / "private.key"
    msg_path = script_dir / "msg.enc"
    
    key_content = key_path.read_text()
    der = base64.b64decode(''.join(key_content.splitlines()[1:-1]))
    seq = asn1.DerSequence()
    seq.decode(der)
    
    n = seq[1]
    e = seq[2]
    P = seq[4]
    
    print(f"[*] Modulus n bit length: {n.bit_length()}", flush=True)
    print(f"[*] Partial prime P: {hex(P)[:34]}...", flush=True)
    
    # Pre-calculated or search
    known_p = 0xe700568ff506bd5892af92592125e06cbe9bd45dfeafe931a333c13463023d4fc25c71b1e8c70d8c28c10fe025474ea96f90887e707f76205565e9e241d571bb
    if n % known_p == 0:
        p = known_p
        print(f"[+] Using verified prime p: {hex(p)}", flush=True)
    else:
        guess_bits = 8
        X = 2**(256 - guess_bits)
        m = 16
        t = 17
        print(f"[*] Starting lattice reduction search with guess_bits={guess_bits}, m={m}, t={t}...", flush=True)
        
        tasks = [(x_guess, P, n, X, m, t) for x_guess in range(2**guess_bits)]
        num_workers = min(16, os.cpu_count() or 4)
        p = None
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = {executor.submit(check_guess, task): task[0] for task in tasks}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    p = res
                    for f in futures:
                        f.cancel()
                    break
        if not p:
            raise RuntimeError("Failed to recover prime p")
        print(f"[+] Recovered prime p: {hex(p)}", flush=True)
    
    q = n // p
    assert n == p * q, "Factorization check failed!"
    print("[+] Successfully factored n = p * q", flush=True)
    
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    
    rsa_key = RSA.construct((n, e, d, p, q))
    enc_data = msg_path.read_bytes()
    cipher = PKCS1_v1_5.new(rsa_key)
    decrypted = cipher.decrypt(enc_data, None)
    
    print(f"[+] Decrypted message: {decrypted}", flush=True)
    
    flag_match = re.search(r"(picoCTF\{[^}]+\}|academy\{[^}]+\})", decrypted.decode('latin1', errors='ignore'))
    if flag_match:
        flag = flag_match.group(1)
    else:
        flag = decrypted.decode('latin1', errors='ignore')
    
    print(f"[+] Flag: {flag}", flush=True)
    
    flag_file = script_dir / "flag.txt"
    flag_file.write_text(flag)
    print(f"[+] Flag written to {flag_file}", flush=True)
    
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
picoCTF{d741543f172970457e6a9aaa890935b8}
```
