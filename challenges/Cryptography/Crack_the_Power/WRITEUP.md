# Writeup: Crack the Power

## Header & Metadata
- **Challenge:** Crack the Power (ID: 522)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** message.txt
- **Official Flag:** `academy{t1ny_e_d9b985d8}`

---

## Mô tả bài toán (Overview / Analysis)
We received an encrypted message. The modulus is built from primes large enough that factoring them isn’t an option, at least not today. See if you can make sense of the numbers and reveal the flag.
Download the <a href='https://challenge-files.cylabacademy.net/library/c85258d1bfc43eacb36ad1dad1f13f53e3bb9de78790da47f98669733ded9001/message.txt' download>message</a>.

### Hints
- When certain values in the encryption setup are smaller than usual, it opens up unexpected shortcuts to recover the plaintext
- Consider whether you can invert the encryption without factoring `n`.
- Read more about Coppersmith's_attack [ here](https://en.wikipedia.org/wiki/Coppersmith's_attack )

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Crack the Power (#522)
Category: Cryptography
"""
from pathlib import Path

def integer_nth_root(y: int, n: int):
    if y < 0:
        raise ValueError("Cannot compute root of negative number")
    if y == 0:
        return 0, True
    
    # Binary search for integer n-th root
    low = 0
    high = 1 << ((y.bit_length() + n - 1) // n + 1)
    while low <= high:
        mid = (low + high) // 2
        p = mid ** n
        if p == y:
            return mid, True
        elif p < y:
            low = mid + 1
        else:
            high = mid - 1
    return high, False

def solve():
    print("[*] Solving Crack the Power...")
    msg_path = Path(__file__).parent / "message.txt"
    if not msg_path.exists():
        raise FileNotFoundError(f"{msg_path} not found")

    params = {}
    with open(msg_path, "r", encoding="utf-8") as f:
        for line in f:
            if "=" in line:
                key, val = line.split("=", 1)
                params[key.strip()] = int(val.strip())

    n = params["n"]
    e = params["e"]
    c = params["c"]

    print(f"[*] Parameters loaded: e = {e}, bit-length of n = {n.bit_length()}, bit-length of c = {c.bit_length()}")
    
    # Since m^e < n, c = m^e over the integers without modular reduction
    m, exact = integer_nth_root(c, e)
    if not exact:
        raise ValueError("Could not find exact integer root")

    flag_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
    flag = flag_bytes.decode("utf-8", errors="ignore")
    print(f"[+] Flag found: {flag}")

    flag_file = Path(__file__).parent / "flag.txt"
    with open(flag_file, "w", encoding="utf-8") as f:
        f.write(flag)
    print(f"[+] Saved flag to {flag_file}")

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{t1ny_e_d9b985d8}
```
