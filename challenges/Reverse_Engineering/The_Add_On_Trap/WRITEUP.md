# Writeup: The Add/On Trap

## Header & Metadata
- **Challenge:** The Add/On Trap (ID: 697)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** suspicious.zip
- **Official Flag:** `academy{Us3_4dd/0ns_v3ry_c4r3fully1}`

---

## Mô tả bài toán (Overview / Analysis)
What kind of information can an Add/On reach? Is it possible to exfiltrate them without me noticing? Do they really do what they say? Most importantly, when to eat? These and many other questions Add/On users should be asking themselves.

Download the provided browser extension and inspect it to uncover the hidden flag:

- <a href='https://challenge-files.cylabacademy.net/library/ba1d9edf14b6cb9cf90cb78eae4378c0e41f32f2ae4491251502e18d124d93aa/suspicious.zip' download>Download the .xpi</a>, password `academy`


### Hints
- What kind of file is one ending in `.xpi`?
- Which modern Python scheme uses url-safe Base64 32-byte keys?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for The Add/On Trap (#697)
Category: Reverse Engineering
"""

import io
import re
import zipfile
from pathlib import Path
from cryptography.fernet import Fernet


def load_connection_config(config_path="connection.cfg"):
    config = {}
    path = Path(config_path)
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    config[key.strip()] = val.strip()
    return config


def solve():
    print("[*] Solving The Add/On Trap...", flush=True)

    # Dynamically load connection config if present
    _cfg = load_connection_config()

    zip_path = Path("suspicious.zip")
    if not zip_path.exists():
        raise FileNotFoundError(f"Missing {zip_path}")

    # Extract XPI from suspicious.zip using password 'academy'
    print("[*] Extracting .xpi from suspicious.zip...", flush=True)
    with zipfile.ZipFile(zip_path) as outer_zip:
        outer_zip.setpassword(b"academy")
        xpi_name = [name for name in outer_zip.namelist() if name.endswith(".xpi")][0]
        xpi_bytes = outer_zip.read(xpi_name)

    # Read files from XPI archive
    print(f"[*] Inspecting {xpi_name}...", flush=True)
    with zipfile.ZipFile(io.BytesIO(xpi_bytes)) as xpi_zip:
        main_js = xpi_zip.read("background/main.js").decode("utf-8")

    # Extract key and encrypted webhook URL
    key_match = re.search(r'const\s+key\s*=\s*["\']([^"\']+)["\']', main_js)
    webhook_match = re.search(r'const\s+webhookUrl\s*=\s*["\']([^"\']+)["\']', main_js)

    if not key_match or not webhook_match:
        raise ValueError("Could not find key or webhookUrl in background/main.js")

    key_b64 = key_match.group(1).encode("utf-8")
    webhook_token = webhook_match.group(1).encode("utf-8")

    print(f"[*] Found Fernet key: {key_b64.decode('utf-8')}", flush=True)
    print(f"[*] Found encrypted token: {webhook_token.decode('utf-8')}", flush=True)

    # Decrypt Fernet token
    fernet = Fernet(key_b64)
    decrypted_bytes = fernet.decrypt(webhook_token)
    flag_candidate = decrypted_bytes.decode("utf-8").strip()

    # Flag verification & decoy checks
    flag_match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", flag_candidate)
    if not flag_match:
        raise ValueError(f"Decrypted text does not match flag format: {flag_candidate}")

    flag = flag_match.group(1)
    for decoy in ["decoy", "fake", "honeypot", "dummy"]:
        if decoy in flag.lower():
            raise ValueError(f"Decoy flag detected: {flag}")

    print(f"[+] Flag found: {flag}", flush=True)

    # Save to flag.txt
    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag + "\n")

    return flag


if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{Us3_4dd/0ns_v3ry_c4r3fully1}
```
