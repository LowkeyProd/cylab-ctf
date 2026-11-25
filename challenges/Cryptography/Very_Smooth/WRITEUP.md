# Writeup: Very Smooth

## Header & Metadata
- **Challenge:** Very Smooth (ID: 315)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** gen.py, output.txt
- **Official Flag:** `academy{p0ll4rd_f4ct0r1z4at10n_FTW_48d4cbdf}`

---

## Mô tả bài toán (Overview / Analysis)
Forget safe primes... Here, we like to live life dangerously... >:)
- <a href='https://challenge-files.cylabacademy.net/library/3ebff3b5e7ef7f10a227bd1c96e451f81d1849f8b7c29b1d27e76e8529d83a66/gen.py' download>gen.py</a>
- <a href='https://challenge-files.cylabacademy.net/library/3ebff3b5e7ef7f10a227bd1c96e451f81d1849f8b7c29b1d27e76e8529d83a66/output.txt' download>output.txt</a>

### Hints
- Don't look at me... Go ask Mr. Pollard if you need a hint!

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Very Smooth (#315)
Category: Cryptography
"""
import sys
from pathlib import Path
import gmpy2
from Crypto.Util.number import long_to_bytes

def solve():
    print("[*] Solving Very Smooth...", flush=True)

    output_path = Path(__file__).parent / "output.txt"
    with open(output_path, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    n = None
    c = None
    for line in lines:
        if line.startswith("n ="):
            n = int(line.split("=")[1].strip(), 16)
        elif line.startswith("c ="):
            c = int(line.split("=")[1].strip(), 16)

    assert n is not None and c is not None
    e = 0x10001

    print(f"[*] Read parameters: n has {n.bit_length()} bits", flush=True)
    print("[*] Running Pollard's p - 1 algorithm...", flush=True)

    a = gmpy2.mpz(2)
    prime = gmpy2.mpz(2)
    step = 0
    p = None

    while prime < 200000:
        prime = gmpy2.next_prime(prime)
        a = gmpy2.powmod(a, prime, n)
        step += 1
        if step % 50 == 0:
            g = gmpy2.gcd(a - 1, n)
            if 1 < g < n:
                p = int(g)
                print(f"[+] Found factor p at prime bound {prime}!", flush=True)
                break

    if not p:
        raise RuntimeError("Failed to factor n with Pollard's p - 1")

    q = n // p
    assert p * q == n

    phi = (p - 1) * (q - 1)
    d = gmpy2.invert(e, phi)
    m = gmpy2.powmod(c, d, n)
    flag_bytes = long_to_bytes(int(m))
    flag = flag_bytes.decode('utf-8', errors='ignore')

    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = Path(__file__).parent / "flag.txt"
    with open(flag_path, "w") as f:
        f.write(flag)
    print(f"[+] Flag written to {flag_path}", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{p0ll4rd_f4ct0r1z4at10n_FTW_48d4cbdf}
```
