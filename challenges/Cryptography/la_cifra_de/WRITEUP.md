# Writeup: la cifra de

## Header & Metadata
- **Challenge:** la cifra de (ID: 3)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `nc xebec.cylabacademy.net 44386`
- **Attached Files:** None
- **Official Flag:** `academy{b311a50_0r_v1gn3r3_c1ph3r181ba1aa}`

---

## Mô tả bài toán (Overview / Analysis)
I found this cipher in an old book.
Can you figure out what it says? Connect with `nc xebec.cylabacademy.net 44386`.

### Hints
- There are tools that make this easy.
- Perhaps looking at history will help

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Deterministic solver for "la cifra de" (Cryptography / Medium)
Decrypts polyalphabetic Vigenère ciphertext with key 'flag'.
"""
import socket
import re
import string
import sys
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = None, 0
    if cfg_file.exists():
        for line in cfg_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("HOST=") and line.split("=", 1)[1]:
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def fetch_ciphertext(host, port, timeout=5):
    print(f"[*] Attempting network connection to {host}:{port}...", flush=True)
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(3.0)
        chunks = []
        try:
            while True:
                data = s.recv(4096)
                if not data:
                    break
                chunks.append(data)
        except (socket.timeout, ConnectionResetError):
            pass
        raw = b"".join(chunks).decode("utf-8", errors="ignore")
    return raw

def decrypt_vigenere(text, key="flag"):
    """
    Classical Vigenère decryption.
    Only Latin alphabetic characters (A-Z, a-z) advance the keystream.
    Punctuation, whitespace, digits, and accented characters are preserved unchanged.
    """
    res = []
    ki = 0
    key_len = len(key)
    for c in text:
        if c in string.ascii_uppercase:
            k = ord(key[ki % key_len].lower()) - ord('a')
            res.append(chr((ord(c) - ord('A') - k) % 26 + ord('A')))
            ki += 1
        elif c in string.ascii_lowercase:
            k = ord(key[ki % key_len].lower()) - ord('a')
            res.append(chr((ord(c) - ord('a') - k) % 26 + ord('a')))
            ki += 1
        else:
            res.append(c)
    return "".join(res)

def solve():
    host, port = get_target_conn()
    raw = None
    if host and port > 0:
        try:
            raw = fetch_ciphertext(host, port)
        except Exception as e:
            print(f"[-] Network connection failed: {e}, falling back to local cached ciphertext.", flush=True)

    cache_file = Path(__file__).resolve().parent / "ciphertext.enc"
    if not raw and cache_file.exists():
        print(f"[*] Reading ciphertext from {cache_file.name}...", flush=True)
        raw = cache_file.read_text(encoding="utf-8")

    if not raw:
        raise RuntimeError("No ciphertext available from network or cache.")

    # Strip BOM and optional banner header
    cleaned = raw.replace("\ufeff", "")
    header = "Encrypted message:\n"
    if cleaned.startswith(header):
        ciphertext = cleaned[len(header):]
    else:
        ciphertext = cleaned

    decrypted = decrypt_vigenere(ciphertext, key="flag")

    pattern = r'(?:academy|picoCTF)\{[^}]+\}'
    match = re.search(pattern, decrypted)
    if not match:
        raise ValueError(f"Flag pattern not found in decrypted text:\n{decrypted}")

    flag = match.group(0).strip()

    # Reject decoys
    decoys = ['decoy', 'fake', 'honeypot', 'dummy', 'not_the_flag']
    if any(d in flag.lower() for d in decoys):
        raise ValueError(f"Flag rejected as potential decoy: {flag}")

    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag, encoding="utf-8")

    print(f"[*] Decrypted Flag: {flag}", flush=True)
    print(flag, flush=True)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{b311a50_0r_v1gn3r3_c1ph3r181ba1aa}
```
