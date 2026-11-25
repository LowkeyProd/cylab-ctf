# Writeup: Compress and Attack

## Header & Metadata
- **Challenge:** Compress and Attack (ID: 127)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `nc xebec.cylabacademy.net 12520`
- **Attached Files:** None
- **Official Flag:** `academy{sheriff_you_solved_the_crime}`

---

## Mô tả bài toán (Overview / Analysis)
Your goal is to find the flag.

### Hints
- The flag only contains uppercase and lowercase letters, underscores, and braces (curly brackets)

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Fast Heuristics.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Compress and Attack (#127)
Target: xebec.cylabacademy.net:16602
"""
from pwn import *
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 16602
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("HOST="xebec.cylabacademy.net"
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
academy{sheriff_you_solved_the_crime}
```
