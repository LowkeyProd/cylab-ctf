# Writeup: Undo

## Header & Metadata
- **Challenge:** Undo (ID: 766)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `nc xebec.cylabacademy.net 30180`
- **Attached Files:** None
- **Official Flag:** `academy{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}`

---

## Mô tả bài toán (Overview / Analysis)
Can you reverse a series of Linux text transformations to recover the original flag?
Start searching for the flag here `nc xebec.cylabacademy.net 30180`

### Hints
- For text translation and character replacement, see [`tr` command documentation](https://man7.org/linux/man-pages/man1/tr.1.html).

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Undo (#766)
Category: General Skills
"""
import re
import socket
import sys
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 30180
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

def determine_command(hint: str) -> str:
    h = hint.lower()
    if "base64" in h:
        return "base64 -d"
    elif "reverse" in h:
        return "rev"
    elif "underscore" in h and "dash" in h:
        return "tr '-' '_'"
    elif "parentheses" in h or "curly" in h:
        return "tr '()' '{}'"
    elif "rot13" in h:
        return "tr 'A-Za-z' 'N-ZA-Mn-za-m'"
    else:
        raise ValueError(f"Unknown transformation hint: {hint}")

def is_decoy(flag: str) -> bool:
    decoys = ["fake", "decoy", "honey", "not_the_flag", "dummy"]
    return any(d in flag.lower() for d in decoys)

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)

    flag = None
    with socket.create_connection((host, port), timeout=15) as s:
        s.settimeout(8)
        accumulated = ""
        while True:
            try:
                chunk = s.recv(4096).decode(errors="replace")
                if not chunk:
                    break
                accumulated += chunk
                sys.stdout.write(chunk)
                sys.stdout.flush()

                # Check if flag appeared
                match = re.search(r"(academy\{[a-zA-Z0-9_@!?-]+\}|picoCTF\{[a-zA-Z0-9_@!?-]+\})", accumulated)
                if match:
                    candidate = match.group(1)
                    if not is_decoy(candidate):
                        flag = candidate
                        break

                # Check if waiting for input
                if "Enter the Linux command to reverse it:" in accumulated:
                    # Find hint
                    hint = ""
                    for line in accumulated.splitlines():
                        line = line.strip()
                        if line.startswith("Hint:"):
                            hint = line
                    cmd = determine_command(hint)
                    print(f"\n[+] Sending command: {cmd}", flush=True)
                    s.sendall((cmd + "\n").encode())
                    # Clear accumulated prompt marker to wait for next step
                    accumulated = ""

            except socket.timeout:
                break

    if flag:
        print(f"\n[+] Recovered Flag: {flag}", flush=True)
        flag_file = Path(__file__).resolve().parent / "flag.txt"
        flag_file.write_text(flag.strip())
        print(f"[+] Flag written to {flag_file}", flush=True)
    else:
        print("\n[-] Failed to find flag", flush=True)
        sys.exit(1)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{Revers1ng_t3xt_Tr4nsf0rm@t10ns_c77d80cc}
```
