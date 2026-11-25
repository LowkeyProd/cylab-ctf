# Writeup: Based

## Header & Metadata
- **Challenge:** Based (ID: 35)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `nc chatelaine.cylabacademy.net 32217`
- **Attached Files:** None
- **Official Flag:** `academy{learning_about_converting_values_c51c32E4}`

---

## Mô tả bài toán (Overview / Analysis)
To get truly 1337, you must understand different data encodings, such as hexadecimal or binary. Can you get the flag from this program to prove you are on the way to becoming 1337?

### Hints
- I hear python can convert things.
- It might help to have multiple windows open.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity following writeup instructions.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Based (#35)
"""
import socket
import re
import sys
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 32217
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

def decode_payload(text):
    m = re.search(r"Please give (?:me )?the (.*?) as a word", text)
    if not m:
        m = re.search(r"give (?:me )?the (.*?) as a word", text, re.IGNORECASE)
    if not m:
        print(f"[!] Could not match prompt in: {text}", flush=True)
        return None
    raw = m.group(1).strip()
    print(f"[*] Raw encoded data: '{raw}'", flush=True)
    
    parts = raw.split()

    # 1. Binary: all tokens are 0/1 and length 7 or 8 (or multiple tokens of 0/1)
    if parts and all(re.fullmatch(r'[01]{7,8}', p) for p in parts):
        res = "".join(chr(int(b, 2)) for b in parts)
        print(f"[*] Decoded from binary: {res}", flush=True)
        return res

    # 2. Octal: multiple tokens, each 1-3 octal digits with value < 256
    if len(parts) > 1 and all(re.fullmatch(r'[0-7]{1,3}', p) and int(p, 8) < 256 for p in parts):
        res = "".join(chr(int(o, 8)) for o in parts)
        print(f"[*] Decoded from octal: {res}", flush=True)
        return res

    # 3. Hexadecimal: even length hex string
    clean_hex = raw.replace(" ", "")
    if len(clean_hex) % 2 == 0 and re.fullmatch(r'[0-9a-fA-F]+', clean_hex):
        try:
            res = bytes.fromhex(clean_hex).decode('ascii')
            print(f"[*] Decoded from hex: {res}", flush=True)
            return res
        except Exception as e:
            print(f"[!] Hex decode error: {e}", flush=True)

    # Fallback checks
    # Maybe single octal number?
    if len(parts) == 1 and re.fullmatch(r'[0-7]{1,3}', parts[0]) and int(parts[0], 8) < 256:
        res = chr(int(parts[0], 8))
        print(f"[*] Decoded single octal: {res}", flush=True)
        return res

    print(f"[!] Unknown encoding for: {raw}", flush=True)
    return None

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)
    s = socket.create_connection((host, port), timeout=15)
    
    full_output = ""
    flag = None

    while True:
        buf = ""
        while True:
            chunk = s.recv(1024).decode(errors="ignore")
            if not chunk:
                break
            buf += chunk
            full_output += chunk
            print(chunk, end="", flush=True)
            if "Input:" in buf or "flag" in buf or "academy{" in buf or "picoCTF{" in buf:
                break
        
        if not buf:
            break

        # Check if flag is in full_output
        m_flag = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', full_output)
        if m_flag:
            flag = m_flag.group(1)
            break

        if "Input:" in buf:
            ans = decode_payload(buf)
            if ans is None:
                print("[!] Failed to decode answer!", flush=True)
                break
            s.sendall((ans + "\n").encode())
            print(f"[Sent]: {ans}", flush=True)
        else:
            # Maybe waiting for more data
            pass

    # Read any leftover data
    try:
        s.settimeout(2.0)
        while True:
            chunk = s.recv(1024).decode(errors="ignore")
            if not chunk:
                break
            full_output += chunk
            print(chunk, end="", flush=True)
    except Exception:
        pass

    s.close()

    # Search for flag again
    m_flag = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', full_output)
    if m_flag:
        flag = m_flag.group(1)

    if flag:
        print(f"\n[+] Flag found: {flag}", flush=True)
        # Check decoy
        if any(d in flag.lower() for d in ['decoy', 'fake', 'honeypot', 'dummy', 'not_the_flag']):
            print("[!] Decoy flag detected, rejecting!", flush=True)
            return None
        out_flag = Path(__file__).resolve().parent / "flag.txt"
        out_flag.write_text(flag.strip() + "\n")
        print(f"[+] Saved flag to {out_flag}", flush=True)
        return flag
    else:
        print("\n[-] Flag not found.", flush=True)
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{learning_about_converting_values_c51c32E4}
```
