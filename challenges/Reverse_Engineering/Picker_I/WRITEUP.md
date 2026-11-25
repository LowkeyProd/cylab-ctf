# Writeup: Picker I

## Header & Metadata
- **Challenge:** Picker I (ID: 400)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `nc xebec.cylabacademy.net 43819`
- **Attached Files:** picker-I.py
- **Official Flag:** `academy{4_d14m0nd_1n_7h3_r0ugh_193d362d}`

---

## Mô tả bài toán (Overview / Analysis)
This service can provide you with a random number, but can it do anything else?
Connect to the program with netcat:

`$ nc xebec.cylabacademy.net 43819`

The program's source code can be downloaded <a href='https://challenge-files.cylabacademy.net/library/c806d08679ff49d0ed9a45bf194bad9171a2d76550391ebda3c3a6c6eeb78e03/picker-I.py' download>here</a>.

### Hints
- Can you point the program to a function that does something useful for you?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Deterministic solve script for Picker I (#400)
Target: xebec.cylabacademy.net:43819
"""
import socket
import re
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 43819
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
    s = socket.socket()
    s.settimeout(10)
    s.connect((host, port))

    prompt = s.recv(1024).decode(errors="ignore")
    print(f"[*] Banner received:\n{prompt}")

    # Send 'win' function name
    s.sendall(b"win\n")
    res = s.recv(4096).decode(errors="ignore")
    s.close()

    print(f"[*] Raw response:\n{res}")

    # Extract hex tokens
    hex_tokens = re.findall(r"0x[0-9a-fA-F]+", res)
    if not hex_tokens:
        raise ValueError("No hex tokens found in response")

    flag = "".join(chr(int(h, 16)) for h in hex_tokens)
    print(f"[+] Recovered flag: {flag}")

    # Save to flag.txt
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag.strip() + "\n")
    print(f"[+] Flag written to {flag_file}")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{4_d14m0nd_1n_7h3_r0ugh_193d362d}
```
