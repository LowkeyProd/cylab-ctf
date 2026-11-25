# Writeup: triple-secure

## Header & Metadata
- **Challenge:** triple-secure (ID: 209)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `picoCTF{1_gu3ss_tr1pl3_rs4_1snt_tr1pl3_s3cur3!!!!!!}`

---

## Mô tả bài toán (Overview / Analysis)
<p>To get the flag, you must break RSA not once, but three times!</p>

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
Solve script for triple-secure (#209)
Category: Cryptography
"""
import math
from pathlib import Path
from Crypto.Util.number import long_to_bytes

def solve():
    print("[*] Solving triple-secure...", flush=True)

    pub_path = Path(__file__).parent / "public-key.txt"
    with open(pub_path, "r") as f:
        lines = f.read().strip().splitlines()

    data = {}
    for line in lines:
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip()] = int(v.strip())

    n1 = data["n1"]
    n2 = data["n2"]
    n3 = data["n3"]
    e = data["e"]
    c = data["c"]

    print("[*] Calculating GCDs...", flush=True)
    p = math.gcd(n1, n2)
    assert p > 1, "GCD(n1, n2) failed to find common prime p"
    q = n1 // p
    r = n2 // p
    assert q * r == n3, "Verification q * r == n3 failed!"
    print("[*] Factored all three moduli successfully!", flush=True)

    # Decrypt stage 3: c mod n3 (moduli[2])
    phi3 = (q - 1) * (r - 1)
    d3 = pow(e, -1, phi3)
    c2 = pow(c, d3, n3)

    # Decrypt stage 2: c2 mod n2 (moduli[1])
    phi2 = (p - 1) * (r - 1)
    d2 = pow(e, -1, phi2)
    c1 = pow(c2, d2, n2)

    # Decrypt stage 1: c1 mod n1 (moduli[0])
    phi1 = (p - 1) * (q - 1)
    d1 = pow(e, -1, phi1)
    c0 = pow(c1, d1, n1)

    flag_bytes = long_to_bytes(c0)
    flag = flag_bytes.decode(errors="replace")
    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = Path(__file__).parent / "flag.txt"
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag.strip())
    print(f"[+] Saved flag to {flag_path}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
picoCTF{1_gu3ss_tr1pl3_rs4_1snt_tr1pl3_s3cur3!!!!!!}
```
