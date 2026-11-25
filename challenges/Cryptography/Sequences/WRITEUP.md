# Writeup: Sequences

## Header & Metadata
- **Challenge:** Sequences (ID: 297)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** sequences.py
- **Official Flag:** `academy{b1g_numb3rs_f5b03a75}`

---

## Mô tả bài toán (Overview / Analysis)
I wrote this linear recurrence function, can you figure out how to make it run
fast enough and get the flag?
Download the code here <a href='https://challenge-files.cylabacademy.net/library/45d82e383fd50225799f78790618dca400da46d59748762e022b12e4aafaebd3/sequences.py' download>sequences.py</a>

Note that even an efficient solution might take several seconds to run. If your
solution is taking several minutes, then you may need to reconsider your
approach.

### Hints
- Google "matrix diagonalization". Can you figure out how to apply it to this
  function?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Sequences (#297)
Category: Cryptography
"""
import sys
import math
import hashlib
from fractions import Fraction
from pathlib import Path

# Increase integer string conversion limit for 10000-digit number
sys.set_int_max_str_digits(0)

ITERS = int(2e7)
VERIF_KEY = "96cc5f3b460732b442814fd33cf8537c"
from sequences import ENCRYPTED_FLAG

def lcm(a, b):
    return abs(a * b) // math.gcd(a, b)

def solve():
    print("[*] Solving Sequences...", flush=True)

    # Characteristic polynomial: x^4 - 21*x^3 - 301*x^2 + 9549*x - 55692 = 0
    # Roots: r1 = -21, r2 = 17, r3 = 13, r4 = 12
    # m(i) = c1 * (-21)^i + c2 * 17^i + c3 * 13^i + c4 * 12^i
    # Initial conditions: m(0) = 1, m(1) = 2, m(2) = 3, m(3) = 4
    # Solving the Vandermonde system yields:
    c1 = Fraction(403, 10659)
    c2 = Fraction(253, 76)
    c3 = Fraction(-1727, 68)
    c4 = Fraction(760, 33)

    D = lcm(lcm(c1.denominator, c2.denominator), lcm(c3.denominator, c4.denominator))

    k1 = c1.numerator * (D // c1.denominator)
    k2 = c2.numerator * (D // c2.denominator)
    k3 = c3.numerator * (D // c3.denominator)
    k4 = c4.numerator * (D // c4.denominator)

    MOD = 10**10000
    BIG_MOD = D * MOD

    print("[*] Computing modular powers...", flush=True)
    t1 = (k1 * pow(-21, ITERS, BIG_MOD)) % BIG_MOD
    t2 = (k2 * pow(17, ITERS, BIG_MOD)) % BIG_MOD
    t3 = (k3 * pow(13, ITERS, BIG_MOD)) % BIG_MOD
    t4 = (k4 * pow(12, ITERS, BIG_MOD)) % BIG_MOD

    tot = (t1 + t2 + t3 + t4) % BIG_MOD
    if tot % D != 0:
        raise ValueError("Sum is not divisible by common denominator D")

    sol = (tot // D) % MOD
    sol_str = str(sol)

    print("[*] Verifying solution hash...", flush=True)
    sol_md5 = hashlib.md5(sol_str.encode()).hexdigest()
    if sol_md5 != VERIF_KEY:
        print(f"[-] Verification failed! Expected {VERIF_KEY}, got {sol_md5}", flush=True)
        sys.exit(1)

    print("[+] Verification key matched!", flush=True)
    key = hashlib.sha256(sol_str.encode()).digest()
    flag = bytearray([char ^ key[i] for i, char in enumerate(ENCRYPTED_FLAG)]).decode()

    print(f"[+] Flag found: {flag}", flush=True)

    Path("flag.txt").write_text(flag)
    print("[+] Saved flag to flag.txt", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{b1g_numb3rs_f5b03a75}
```
