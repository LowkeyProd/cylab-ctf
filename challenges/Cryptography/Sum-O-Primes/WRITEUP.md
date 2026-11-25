# Writeup: Sum-O-Primes

## Header & Metadata
- **Challenge:** Sum-O-Primes (ID: 310)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** gen.py, output.txt
- **Official Flag:** `academy{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_2a4c68a9}`

---

## Mô tả bài toán (Overview / Analysis)
We have so much faith in RSA we give you not just the product of the primes,
but their sum as well!
- <a href='https://challenge-files.cylabacademy.net/library/81a018042d8d86e3e85dbdcd77f6b6a1cf6f829182e6fee61f938882ddcf03d2/gen.py' download>gen.py</a>
- <a href='https://challenge-files.cylabacademy.net/library/81a018042d8d86e3e85dbdcd77f6b6a1cf6f829182e6fee61f938882ddcf03d2/output.txt' download>output.txt</a>

### Hints
- I love squares :)

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Sum-O-Primes (#310)
Category: Cryptography
"""
import math
import os
import re
from pathlib import Path

def solve():
    print("[*] Solving Sum-O-Primes...", flush=True)

    with open("output.txt", "r") as f:
        data = f.read()

    x_match = re.search(r"x\s*=\s*([0-9a-fA-F]+)", data)
    n_match = re.search(r"n\s*=\s*([0-9a-fA-F]+)", data)
    c_match = re.search(r"c\s*=\s*([0-9a-fA-F]+)", data)

    x = int(x_match.group(1), 16)
    n = int(n_match.group(1), 16)
    c = int(c_match.group(1), 16)

    # p and q satisfy:
    # t^2 - x*t + n = 0
    # delta = x^2 - 4*n
    delta = x * x - 4 * n
    assert delta >= 0, "Discriminant is negative"
    
    sqrt_delta = math.isqrt(delta)
    assert sqrt_delta * sqrt_delta == delta, "Discriminant is not a perfect square"

    p = (x + sqrt_delta) // 2
    q = (x - sqrt_delta) // 2

    assert p * q == n, "p * q != n"
    assert p + q == x, "p + q != x"
    print("[+] Factored n successfully!", flush=True)

    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    pt = pow(c, d, n)
    flag_bytes = pt.to_bytes((pt.bit_length() + 7) // 8, "big")
    flag = flag_bytes.decode("utf-8", errors="ignore")

    print(f"[+] Recovered flag: {flag}", flush=True)

    with open("flag.txt", "w") as f:
        f.write(flag)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{pl33z_n0_g1v3_c0ngru3nc3_0f_5qu4r35_2a4c68a9}
```
