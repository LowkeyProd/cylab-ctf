# Writeup: what's a net cat?

## Header & Metadata
- **Challenge:** what's a net cat? (ID: 34)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `academy{nEtCat_Mast3ry_eb8Afcd3}`

---

## Mô tả bài toán (Overview / Analysis)

Using netcat (nc) is going to be pretty important. Can you connect to `xebec.cylabacademy.net` at port `43155` to get the flag?

### Hints
- nc [tutorial](https://linux.die.net/man/1/nc)

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for what's a net cat? (#34)
Category: General Skills
"""
import os
import re
import socket
from pathlib import Path

def parse_connection_cfg(cfg_path: Path):
    config = {}
    if cfg_path.exists():
        for line in cfg_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            config[key.strip()] = val.strip()
    return config

def solve():
    print("[*] Solving what's a net cat?...")
    cfg_file = Path(__file__).parent / "connection.cfg"
    config = parse_connection_cfg(cfg_file)

    host = config.get("HOST") or "xebec.cylabacademy.net"
    port_str = config.get("PORT")
    port = int(port_str) if port_str and port_str != "0" else 43155

    print(f"[*] Connecting to {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((host, port))

    response = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break
    s.close()

    text = response.decode("utf-8", errors="replace")
    print(f"[*] Received response:\n{text}")

    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", text)
    if not match:
        raise ValueError(f"Could not find flag in response: {text}")

    flag = match.group(1)
    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag.strip() + "\n")
    print(f"[+] Flag found: {flag}")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{nEtCat_Mast3ry_eb8Afcd3}
```
