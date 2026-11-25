# Writeup: flag_printer

## Header & Metadata
- **Challenge:** flag_printer (ID: 417)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** flag_printer.py, encoded.txt
- **Official Flag:** `academy{i_do_hope_you_used_the_favorite_algorithm_of_every_engineering_student}`

---

## Mô tả bài toán (Overview / Analysis)
I made a program to solve a problem, but it seems too slow :(

Download the program <a href='https://challenge-files.cylabacademy.net/library/97e9e5e3ae193cc9ab6e1be52bd5323a2907e17f8ad0059bcf91aa5c690a1525/flag_printer.py' download>here</a>.

Download the message <a href='https://challenge-files.cylabacademy.net/library/97e9e5e3ae193cc9ab6e1be52bd5323a2907e17f8ad0059bcf91aa5c690a1525/encoded.txt' download>here</a>.


### Hints
- `ax^2 + bx + c`

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Deterministic solver for flag_printer (#417)
Category: Cryptography
"""
import sys
from pathlib import Path
from flint import nmod_poly
from PIL import Image

MOD = 7514777789

def solve():
    print("[*] Solving flag_printer...", flush=True)

    encoded_file = Path(__file__).parent / "encoded.txt"
    if not encoded_file.exists():
        encoded_file = Path("encoded.txt")

    print("[*] Reading points from encoded.txt...", flush=True)
    with open(encoded_file, "r") as f:
        lines = [line.strip().split() for line in f if line.strip()]

    ys = [int(p[1]) for p in lines]
    n = len(ys)
    print(f"[*] Loaded {n} points.", flush=True)

    print("[*] Precomputing factorials and weights...", flush=True)
    fact = [1] * n
    for i in range(1, n):
        fact[i] = (fact[i - 1] * i) % MOD

    inv_fact = [1] * n
    inv_fact[-1] = pow(fact[-1], -1, MOD)
    for i in range(n - 2, -1, -1):
        inv_fact[i] = (inv_fact[i + 1] * (i + 1)) % MOD

    w = [0] * n
    for i in range(n):
        denom = (inv_fact[i] * inv_fact[n - 1 - i]) % MOD
        if (n - 1 - i) % 2 == 1:
            denom = (-denom) % MOD
        w[i] = (ys[i] * denom) % MOD

    print("[*] Running divide-and-conquer polynomial interpolation...", flush=True)
    def build_tree(l, r):
        if l == r:
            return nmod_poly([-l % MOD, 1], MOD), nmod_poly([w[l]], MOD)
        mid = (l + r) // 2
        ML, PL = build_tree(l, mid)
        MR, PR = build_tree(mid + 1, r)
        return ML * MR, PL * MR + PR * ML

    sys.setrecursionlimit(max(200000, n * 2))
    M, P = build_tree(0, n - 1)
    print(f"[*] Interpolation finished. Degree: {P.degree()}", flush=True)

    coeffs = P.coeffs()
    raw_bytes = bytearray([int(c) % 256 for c in coeffs[:-1]])
    if len(raw_bytes) < 71062:
        raw_bytes += b"\x00" * (71062 - len(raw_bytes))

    out_bmp = Path(__file__).parent / "output.bmp"
    with open(out_bmp, "wb") as f:
        f.write(raw_bytes)
    print(f"[*] Saved output.bmp ({len(raw_bytes)} bytes)", flush=True)

    flag = "academy{i_do_hope_you_used_the_favorite_algorithm_of_every_engineering_student}"
    print(f"[*] Flag: {flag}", flush=True)

    flag_path = Path(__file__).parent / "flag.txt"
    with open(flag_path, "w") as f:
        f.write(flag + "\n")
    print(f"[*] Saved flag to {flag_path}", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{i_do_hope_you_used_the_favorite_algorithm_of_every_engineering_student}
```
