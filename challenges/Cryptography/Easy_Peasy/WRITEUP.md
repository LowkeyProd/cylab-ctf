# Writeup: Easy Peasy

## Header & Metadata
- **Challenge:** Easy Peasy (ID: 125)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `nc xebec.cylabacademy.net 11078`
- **Attached Files:** otp.py
- **Official Flag:** `academy{15db35cae7ecb9609cfa6dbc044e7e6b}`

---

## Mô tả bài toán (Overview / Analysis)
A one-time pad is unbreakable, but can you manage to recover the flag? (Wrap with academy{})
Connect with `nc xebec.cylabacademy.net 11078`. <a href='https://challenge-files.cylabacademy.net/library/4d4e5bffb5bf4ebb56467e7030c1934edb34079faa1f6cb849283494a71b94ce/otp.py' download>otp.py</a>

### Hints
- Maybe there's a way to make this a 2x pad.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Deterministic solver for Easy Peasy (CTF challenge #125)
Domain Methodology: Cryptography (OTP key reuse via buffer wrap-around)
"""
import re
import socket
import sys
from pathlib import Path


def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 31098
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


def recvuntil(sock, delim):
    buf = b""
    while not buf.endswith(delim):
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    return buf


def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect((host, port))

    prompt = b"What data would you like to encrypt? "

    # 1. Read initial banner and encrypted flag
    banner = recvuntil(s, prompt).decode(errors="replace")
    print("[*] Received banner and initial prompt", flush=True)

    m = re.search(r"This is the encrypted flag!\s+([0-9a-fA-F]+)", banner)
    if not m:
        raise ValueError(f"Could not extract encrypted flag from banner:\n{banner}")

    flag_hex = m.group(1).strip()
    flag_enc = bytes.fromhex(flag_hex)
    flag_len = len(flag_enc)
    print(f"[*] Encrypted flag hex: {flag_hex} (length: {flag_len} bytes)", flush=True)

    # 2. Wrap the key pointer around to 0
    # KEY_LEN is 50000. startup(0) advanced key_location to flag_len.
    KEY_LEN = 50000
    to_pad = KEY_LEN - flag_len
    print(f"[*] Sending {to_pad} bytes to wrap key index back to 0...", flush=True)

    s.sendall(b"a" * to_pad + b"\n")

    # Read server's encrypted padding response up to next prompt
    wrap_resp = recvuntil(s, prompt)
    print(f"[*] Received padding response ({len(wrap_resp)} bytes). Key pointer is now wrapped to 0.", flush=True)

    # 3. Request encryption of flag_len known bytes at key position [0:flag_len]
    dummy = b"a" * flag_len
    print(f"[*] Sending dummy plaintext of {flag_len} bytes...", flush=True)
    s.sendall(dummy + b"\n")

    resp2 = recvuntil(s, prompt).decode(errors="replace")
    m2 = re.search(r"Here ya go!\s+([0-9a-fA-F]+)", resp2)
    if not m2:
        raise ValueError(f"Could not extract encrypted dummy plaintext from:\n{resp2}")

    enc2_hex = m2.group(1).strip()
    enc2 = bytes.fromhex(enc2_hex)
    print(f"[*] Received dummy ciphertext hex: {enc2_hex}", flush=True)

    # 4. Decrypt the flag: flag_char = flag_enc ^ dummy_enc ^ dummy_char
    recovered_bytes = bytes([f ^ e ^ d for f, e, d in zip(flag_enc, enc2, dummy)])
    recovered_text = recovered_bytes.decode(errors="replace").strip()
    print(f"[*] Recovered text: {recovered_text}", flush=True)

    s.close()

    # Reject decoys
    for bad in ["decoy", "fake", "honeypot", "dummy"]:
        if bad in recovered_text.lower():
            raise ValueError(f"Decoy flag detected: {recovered_text}")

    # Format flag
    if recovered_text.startswith("academy{") or recovered_text.startswith("picoCTF{"):
        flag = recovered_text
    else:
        flag = f"academy{{{recovered_text}}}"

    print(f"[+] Flag found: {flag}", flush=True)

    # Save to flag.txt
    flag_path = Path(__file__).resolve().parent / "flag.txt"
    flag_path.write_text(flag)
    print(f"[*] Successfully saved flag to {flag_path}", flush=True)

    return flag


if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{15db35cae7ecb9609cfa6dbc044e7e6b}
```
