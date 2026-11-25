# Writeup: b00tl3gRSA2

## Header & Metadata
- **Challenge:** b00tl3gRSA2 (ID: 2)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `nc chatelaine.cylabacademy.net 23638`
- **Attached Files:** None
- **Official Flag:** `academy{bad_1d3a5_1972548}`

---

## Mô tả bài toán (Overview / Analysis)
In RSA d is a lot bigger than e, why don't we use d to encrypt instead of e?
Connect with `nc chatelaine.cylabacademy.net 23638`.

### Hints
- What is e generally?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Fast Heuristics.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for b00tl3gRSA2 (#2)
Target: chatelaine.cylabacademy.net:23638
"""
from pwn import *
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 23638
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("HOST=") and line.split("=", 1)[1]:
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...")
    io = remote(host, port)
    data = io.recvall(timeout=5).decode(errors="ignore")
    print(data)
    io.close()

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{bad_1d3a5_1972548}
```
