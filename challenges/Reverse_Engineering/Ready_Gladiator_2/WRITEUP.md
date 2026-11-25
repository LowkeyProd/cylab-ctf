# Writeup: Ready Gladiator 2

## Header & Metadata
- **Challenge:** Ready Gladiator 2 (ID: 370)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `nc xebec.cylabacademy.net 44416`
- **Attached Files:** imp.red
- **Official Flag:** `academy{d3m0n_3xpung3r_37214f35}`

---

## Mô tả bài toán (Overview / Analysis)
Can you make a CoreWars warrior that wins every single round?
Your opponent is the Imp. The source is available 
<a href='https://challenge-files.cylabacademy.net/library/b25b2968f77e5b5e79fa7896496cfcdc200b9f0d3529f9a1192f90fea4636782/imp.red' download>here</a>. If you wanted to pit the Imp against
himself, you could download the Imp and connect to the CoreWars server like
this:

`nc xebec.cylabacademy.net 44416 < imp.red`

To get the flag, you must beat the Imp all 100 rounds.

### Hints
- If your warrior is close, try again, it may work on subsequent tries... why
  is that?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Ready Gladiator 2 (#370)
Dynamically reads connection parameters from connection.cfg,
submits an Imp-killing warrior in Redcode, and retrieves the flag.
"""
import socket
import re
import sys
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 44416
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
    print(f"[*] Connecting to {host}:{port}...", flush=True)

    warrior = (
        ";redcode\n"
        ";name Imp Killer\n"
        ";assert 1\n"
        "jmp 0, <-2\n"
        "end\n"
        "end\n"
    )

    s = socket.create_connection((host, port), timeout=15)
    
    # Receive initial prompt
    initial = s.recv(1024).decode(errors="ignore")
    print(f"[*] Prompt received:\n{initial}", flush=True)

    print("[*] Sending warrior payload...", flush=True)
    s.sendall(warrior.encode())

    # Read output until EOF or match
    output = ""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            text = chunk.decode(errors="ignore")
            output += text
            print(text, end="", flush=True)
            if "academy{" in output or "picoCTF{" in output:
                break
        except socket.timeout:
            break
    s.close()

    flag_match = re.search(r"(?:academy|picoCTF)\{[^}]+\}", output)
    if flag_match:
        flag = flag_match.group(0)
        print(f"\n[+] Flag found: {flag}", flush=True)
        flag_file = Path(__file__).resolve().parent / "flag.txt"
        flag_file.write_text(flag.strip() + "\n")
        print(f"[+] Flag written to {flag_file}", flush=True)
        return flag
    else:
        print("\n[-] Flag not found in server output", flush=True)
        sys.exit(1)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{d3m0n_3xpung3r_37214f35}
```
