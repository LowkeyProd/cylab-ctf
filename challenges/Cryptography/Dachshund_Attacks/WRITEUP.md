# Writeup: Dachshund Attacks

## Header & Metadata
- **Challenge:** Dachshund Attacks (ID: 159)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `nc xebec.cylabacademy.net 12466`
- **Attached Files:** None
- **Official Flag:** `academy{proving_wiener_ffef507}`

---

## Mô tả bài toán (Overview / Analysis)
What if $$d$$ is too small?
Connect with `nc xebec.cylabacademy.net 12466`.

### Hints
- What do you think about my pet? <a href='https://challenge-files.cylabacademy.net/library/d785fb0fbc5527a85b6b7c45e514e3e63c94e42499e537a59e5f90432c34d983/dachshund.jpg' download>dachshund.jpg</a>

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Dachshund Attacks - Wiener's Attack on RSA
"""
import re
import socket
import math
from pathlib import Path
from Crypto.Util.number import long_to_bytes

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 12466
    if cfg_file.exists():
        for line in cfg_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("HOST=") and line.split("=", 1)[1]:
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def continued_fractions(num, den):
    cf = []
    while den != 0:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf

def convergents(cf):
    p = [0, 1]
    q = [1, 0]
    for a in cf:
        p.append(a * p[-1] + p[-2])
        q.append(a * q[-1] + q[-2])
        yield p[-1], q[-1]

def is_square(n):
    if n < 0:
        return False, 0
    r = int(math.isqrt(n))
    return r * r == n, r

def wiener_attack(e, n):
    cf = continued_fractions(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        is_sq, r = is_square(disc)
        if is_sq:
            p = (s + r) // 2
            if p > 1 and n % p == 0:
                return d
    return None

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)

    with socket.create_connection((host, port), timeout=15) as s:
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            text = buf.decode(errors="ignore")
            if "e:" in text and "n:" in text and "c:" in text:
                # Give a short moment to ensure full line is read
                s.settimeout(1.0)
                try:
                    while True:
                        extra = s.recv(4096)
                        if not extra:
                            break
                        buf += extra
                except (socket.timeout, BlockingIOError):
                    pass
                break

    text = buf.decode(errors="ignore")
    print(f"[*] Received banner:\n{text}", flush=True)

    e_match = re.search(r"e:\s*(\d+)", text)
    n_match = re.search(r"n:\s*(\d+)", text)
    c_match = re.search(r"c:\s*(\d+)", text)

    if not (e_match and n_match and c_match):
        raise ValueError("Failed to parse e, n, or c from server response")

    e = int(e_match.group(1))
    n = int(n_match.group(1))
    c = int(c_match.group(1))

    print(f"[*] Parsed RSA parameters:", flush=True)
    print(f"    e: {e}", flush=True)
    print(f"    n: {n}", flush=True)
    print(f"    c: {c}", flush=True)

    print("[*] Running Wiener's attack...", flush=True)
    d = wiener_attack(e, n)
    if d is None:
        raise ValueError("Wiener's attack failed to find private key d")

    print(f"[+] Found private exponent d: {d}", flush=True)
    m = pow(c, d, n)
    plaintext = long_to_bytes(m)
    print(f"[+] Decrypted plaintext: {plaintext}", flush=True)

    flag_match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", plaintext.decode(errors="ignore"))
    if not flag_match:
        raise ValueError(f"Flag pattern not found in decrypted text: {plaintext}")

    flag = flag_match.group(1)
    print(f"[+] Recovered flag: {flag}", flush=True)

    # Save to flag.txt
    flag_path = Path(__file__).resolve().parent / "flag.txt"
    flag_path.write_text(flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Flag written to {flag_path}", flush=True)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{proving_wiener_ffef507}
```
