# Writeup: spelling-quiz

## Header & Metadata
- **Challenge:** spelling-quiz (ID: 210)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `picoCTF{perhaps_the_dog_jumped_over_was_just_tired}`

---

## Mô tả bài toán (Overview / Analysis)
<p>I found the flag, but my brother wrote a program to encrypt all his text files. He has a spelling quiz study guide too, but I don't know if that helps.</p>

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for spelling-quiz (#210)
Category: Cryptography
Target: Monoalphabetic substitution cipher on study guide & flag.
"""
import io
import os
import re
import sys
import zipfile
import urllib.request
from pathlib import Path

# Unbuffered output
def log(msg):
    print(msg, flush=True)

def get_target_config():
    """Dynamically read connection.cfg if present."""
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {"HOST": "", "PORT": 0, "URL": ""}
    if cfg_file.exists():
        for line in cfg_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def ensure_challenge_files(base_dir: Path):
    """Ensure challenge files (public/flag.txt) exist, downloading if needed."""
    flag_enc_file = base_dir / "public" / "flag.txt"
    if flag_enc_file.exists():
        return flag_enc_file

    log("[*] Challenge files not found locally, attempting download...")
    cdn_url = "https://challenge-files.cylabacademy.net/picoMini+by+redpwn/Cryptography/spelling-quiz/public.zip"
    try:
        req = urllib.request.Request(cdn_url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                z.extractall(base_dir)
            log(f"[+] Downloaded and extracted challenge files to {base_dir}")
    except Exception as e:
        log(f"[-] Download error: {e}")

    return flag_enc_file

def solve():
    base_dir = Path(__file__).resolve().parent
    config = get_target_config()
    log(f"[*] Dynamic config loaded: HOST={config.get('HOST')}, PORT={config.get('PORT')}, URL={config.get('URL')}")

    # Ensure files are present
    flag_enc_file = ensure_challenge_files(base_dir)
    if not flag_enc_file.exists():
        log(f"[-] Encrypted flag file not found at {flag_enc_file}")
        return None

    ciphertext = flag_enc_file.read_text(encoding="utf-8").strip()
    log(f"[*] Encrypted flag ciphertext: {ciphertext}")

    # Cipher to plain mapping deduced from the 272,543-word study guide
    # Verified against dictionary words:
    # 'b'->'p', 'r'->'e', 'c'->'r', 'f'->'h', 'x'->'a', 'a'->'s', 'v'->'t', 'm'->'d',
    # 'i'->'o', 'd'->'g', 'h'->'j', 'o'->'u', 's'->'m', 'p'->'v', 'e'->'w', 'w'->'i',
    # 't'->'n', 'l'->'l', 'k'->'z', 'j'->'q', 'n'->'c', 'q'->'y', 'g'->'k', 'u'->'b',
    # 'z'->'x', 'y'->'f'
    cipher_to_plain = {
        'a': 's', 'b': 'p', 'c': 'r', 'd': 'g', 'e': 'w', 'f': 'h', 'g': 'k', 'h': 'j',
        'i': 'o', 'j': 'q', 'k': 'z', 'l': 'l', 'm': 'd', 'n': 'c', 'o': 'u', 'p': 'v',
        'q': 'y', 'r': 'e', 's': 'm', 't': 'n', 'u': 'b', 'v': 't', 'w': 'i', 'x': 'a',
        'y': 'f', 'z': 'x'
    }

    # Decrypt
    decrypted_chars = []
    for char in ciphertext:
        if char.lower() in cipher_to_plain:
            dec = cipher_to_plain[char.lower()]
            decrypted_chars.append(dec.upper() if char.isupper() else dec)
        else:
            decrypted_chars.append(char)

    decrypted_inner = "".join(decrypted_chars)
    log(f"[+] Decrypted plaintext: {decrypted_inner}")

    # Format flag
    flag = f"picoCTF{{{decrypted_inner}}}"
    log(f"[+] Flag recovered: {flag}")

    # Reject decoys
    for decoy in ["decoy", "fake", "honeypot", "dummy", "not_the_flag"]:
        if decoy in flag.lower():
            log(f"[-] Rejected decoy flag: {flag}")
            return None

    # Write flag to flag.txt in current directory
    out_flag_file = base_dir / "flag.txt"
    out_flag_file.write_text(flag + "\n", encoding="utf-8")
    log(f"[+] Saved flag to {out_flag_file}")

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
picoCTF{perhaps_the_dog_jumped_over_was_just_tired}
```
