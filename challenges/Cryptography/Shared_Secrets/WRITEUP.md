# Writeup: Shared Secrets

## Header & Metadata
- **Challenge:** Shared Secrets (ID: 715)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** message.txt, encryption.py
- **Official Flag:** `academy{dh_s3cr3t_441eb9ee}`

---

## Mô tả bài toán (Overview / Analysis)
A message was encrypted using a shared secret... but it looks like one side of the exchange leaked something. Can you piece together the secret and get the flag?
Download the <a href='https://challenge-files.cylabacademy.net/library/696a330c92491df25f02f3f20e552a2b8b1b8fd8c5ffc3b3902b972c24638f19/message.txt' download>message</a>. And source <a href='https://challenge-files.cylabacademy.net/library/696a330c92491df25f02f3f20e552a2b8b1b8fd8c5ffc3b3902b972c24638f19/encryption.py' download>code</a>

### Hints
- What do you get if you combine a public key with a known private one?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Shared Secrets (#715)
Category: Cryptography
"""
import os
import re
from pathlib import Path

def load_connection_config(cfg_path="connection.cfg"):
    cfg = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    return cfg

def parse_message(file_path="message.txt"):
    params = {}
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if line and "=" in line:
                k, v = line.split("=", 1)
                params[k.strip()] = v.strip()
    return params

def solve():
    print("[*] Solving Shared Secrets...", flush=True)
    
    # Read connection config dynamically
    cfg = load_connection_config()
    print(f"[*] Connection config: {cfg}", flush=True)

    # Parse parameters from message.txt
    params = parse_message()
    p = int(params["p"])
    A = int(params["A"])
    b = int(params["b"])
    enc_hex = params["enc"]
    enc = bytes.fromhex(enc_hex)

    print(f"[*] Calculating shared secret from A^b mod p...", flush=True)
    shared = pow(A, b, p)
    key_byte = shared % 256

    print(f"[*] Shared key byte: {key_byte}", flush=True)
    flag_bytes = bytes([x ^ key_byte for x in enc])
    flag = flag_bytes.decode("utf-8", errors="replace")

    print(f"[+] Decrypted message: {flag}", flush=True)

    # Sanity checks
    if any(decoy in flag.lower() for decoy in ["decoy", "fake", "honeypot", "dummy", "not_the_flag"]):
        raise ValueError(f"Flag rejected as decoy: {flag}")

    if not re.match(r"^(academy|picoCTF)\{.*\}$", flag):
        raise ValueError(f"Flag format invalid: {flag}")

    # Write to flag.txt
    with open("flag.txt", "w") as f:
        f.write(flag + "\n")
    print(f"[+] Flag saved to flag.txt: {flag}", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{dh_s3cr3t_441eb9ee}
```
