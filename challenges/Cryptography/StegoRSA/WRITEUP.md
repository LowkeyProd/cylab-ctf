# Writeup: StegoRSA

## Header & Metadata
- **Challenge:** StegoRSA (ID: 719)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** flag.enc, image.jpg
- **Official Flag:** `academy{rs4_k3y_1n_1mg_42380180}`

---

## Mô tả bài toán (Overview / Analysis)
A message has been encrypted using RSA. The public key is gone… but someone might have been careless with the private key. Can you recover it and decrypt the message?
Download the <a href='https://challenge-files.cylabacademy.net/library/cd170c0e341c181c93172139e85c2b00cb4d64184768c43706a6ac8234903dbe/flag.enc' download>flag</a> and <a href='https://challenge-files.cylabacademy.net/library/cd170c0e341c181c93172139e85c2b00cb4d64184768c43706a6ac8234903dbe/image.jpg' download>image</a>.

### Hints
- Metadata can tell you more than you expect.
- Hex can be turned back into a key file.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for StegoRSA (#719)
Category: Cryptography
"""
import os
import re
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

def load_connection_cfg(cfg_path="connection.cfg"):
    config = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    return config

def extract_hex_comment_from_jpeg(jpeg_path="image.jpg"):
    with open(jpeg_path, "rb") as f:
        data = f.read()

    # Locate COM marker (0xFFFE)
    pos = data.find(b"\xff\xfe")
    if pos == -1:
        raise ValueError("COM marker (0xFFFE) not found in JPEG.")
    
    length = (data[pos + 2] << 8) + data[pos + 3]
    comment_bytes = data[pos + 4 : pos + 2 + length]
    return comment_bytes.decode("ascii").strip().replace("\n", "").replace("\r", "")

def solve():
    print("[*] Solving StegoRSA...", flush=True)
    cfg = load_connection_cfg()
    print(f"[*] Loaded config: {cfg}", flush=True)

    print("[*] Extracting hex-encoded private key from image.jpg metadata...", flush=True)
    hex_str = extract_hex_comment_from_jpeg("image.jpg")
    pem_bytes = bytes.fromhex(hex_str)

    print("[*] Parsing RSA private key...", flush=True)
    rsa_key = RSA.import_key(pem_bytes)
    print(f"[*] Successfully imported RSA key ({rsa_key.size_in_bits()} bits)", flush=True)

    print("[*] Reading flag.enc ciphertext...", flush=True)
    with open("flag.enc", "rb") as f:
        ciphertext = f.read()

    print("[*] Decrypting ciphertext with PKCS1_v1_5...", flush=True)
    cipher = PKCS1_v1_5.new(rsa_key)
    sentinel = b"DECRYPTION_FAILED"
    decrypted = cipher.decrypt(ciphertext, sentinel)

    if decrypted == sentinel:
        raise RuntimeError("Failed to decrypt ciphertext with PKCS1_v1_5")

    flag = decrypted.decode("utf-8", errors="ignore").strip()
    print(f"[+] Decrypted text: {flag}", flush=True)

    # Verification against decoy patterns
    for bad in ["decoy", "fake", "honeypot", "dummy"]:
        if bad in flag.lower():
            raise ValueError(f"Decoy flag detected: {flag}")

    # Verify format
    if not (flag.startswith("academy{") or flag.startswith("picoCTF{")):
        raise ValueError(f"Flag does not match expected format: {flag}")

    # Write flag.txt
    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag)
    print(f"[+] Flag written to flag.txt: {flag}", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{rs4_k3y_1n_1mg_42380180}
```
