# Writeup: Nice netcat...

## Header & Metadata
- **Challenge:** Nice netcat... (ID: 156)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `nc chatelaine.cylabacademy.net 43239`
- **Attached Files:** None
- **Official Flag:** `academy{g00d_k1tty!_n1c3_k1tty!_6d1e6}`

---

## Mô tả bài toán (Overview / Analysis)
There is a nice program that you can talk to by using this command in a shell:
`$ nc chatelaine.cylabacademy.net 43239`, but it doesn't speak English...

### Hints
- You can practice using netcat with this Challenge Library problem: [what's a netcat?](/library/34)
- You can practice reading and writing ASCII with this Challenge Library problem: [Let's Warm Up](/library/22)

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Deterministic solver for Nice netcat... (#156)
Category: General Skills
"""

import os
import re
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 43239
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
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

    raw_data = ""
    with socket.create_connection((host, port), timeout=10) as s:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw_data += chunk.decode("latin-1", errors="ignore")

    print("[*] Received raw numbers stream from server.")
    tokens = raw_data.strip().split()
    chars = []
    for token in tokens:
        if token.isdigit():
            chars.append(chr(int(token)))
        else:
            chars.append(token)

    decoded_text = "".join(chars)
    print(f"[*] Decoded text:\n{decoded_text}")

    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", decoded_text)
    if not match:
        raise ValueError("Flag pattern not found in decoded text!")

    flag = match.group(1).strip()
    print(f"[+] Found flag: {flag}")

    out_file = Path(__file__).resolve().parent / "flag.txt"
    out_file.write_text(flag + "\n")
    print(f"[+] Flag written to {out_file}")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{g00d_k1tty!_n1c3_k1tty!_6d1e6}
```
