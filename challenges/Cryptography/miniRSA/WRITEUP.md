# Writeup: miniRSA

## Header & Metadata
- **Challenge:** miniRSA (ID: 73)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** ciphertext
- **Official Flag:** `academy{n33d_a_lArg3r_e_1106c382}`

---

## Mô tả bài toán (Overview / Analysis)
Let's decrypt this.
Can you decrypt this <a href='https://challenge-files.cylabacademy.net/library/eda4bb1f373e93620b8b14221ab1eee5b035609abf646d329514eb7e99f93c03/ciphertext' download>ciphertext</a>? Something seems a bit small.

### Hints
- RSA [tutorial](https://en.wikipedia.org/wiki/RSA_%28cryptosystem%29)
- How could having too small an e affect the security of this 2048 bit key?
- Make sure you don't lose precision, the numbers are pretty big (besides the e value)

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for miniRSA (#73)
Category: Cryptography

Vulnerability:
With a 2048-bit modulus N and small public exponent e = 3,
the plaintext message m was not padded to the modulus size,
resulting in m^3 < N. Therefore, c = m^3 mod N = m^3 over the integers,
and the plaintext can be recovered by taking the exact integer cube root of c.
"""

import sys
import gmpy2
from Crypto.Util.number import long_to_bytes
from pathlib import Path

def solve():
    print("[*] Solving miniRSA...", flush=True)

    ciphertext_path = Path(__file__).parent / "ciphertext"
    with open(ciphertext_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    N = int(lines[0].split(":")[1].strip())
    e = int(lines[1].split(":")[1].strip())
    c = int(lines[2].split(":")[1].strip())

    print(f"[*] N bit length: {N.bit_length()}", flush=True)
    print(f"[*] e: {e}", flush=True)
    print(f"[*] c bit length: {c.bit_length()}", flush=True)

    # Check for direct integer root (or small multiples k if m^e wrapped around slightly)
    flag = ""
    for k in range(1000):
        val = c + k * N
        root, exact = gmpy2.iroot(val, e)
        if exact:
            print(f"[+] Found exact {e}-th root with k={k}!", flush=True)
            m = int(root)
            recovered = long_to_bytes(m).decode("utf-8", errors="ignore")
            print(f"[+] Decrypted text: {recovered}", flush=True)
            flag = recovered.strip()
            break

    if flag:
        flag_path = Path(__file__).parent / "flag.txt"
        with open(flag_path, "w", encoding="utf-8") as f:
            f.write(flag + "\n")
        print(f"[+] Flag written to {flag_path}: {flag}", flush=True)
    else:
        print("[-] Failed to recover flag.", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{n33d_a_lArg3r_e_1106c382}
```
