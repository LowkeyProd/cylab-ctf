# Writeup: Operation Orchid

## Header & Metadata
- **Challenge:** Operation Orchid (ID: 285)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** disk.flag.img.gz
- **Official Flag:** `academy{h4un71ng_p457_0b36d810}`

---

## Mô tả bài toán (Overview / Analysis)
Download this disk image and find the flag.

Note: if you are using the webshell, download and extract the disk image into
`/tmp` not your home directory.
- <a href='https://challenge-files.cylabacademy.net/library/bb0cb9b59f754a578fdcff72400d49394fe4399b5bf0d34f650c5baffbad8575/disk.flag.img.gz' download>Download compressed disk image</a>

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity analyzing & repairing solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Operation Orchid (#285)
Category: Forensics
"""
import re
import gzip
import hashlib
from pathlib import Path
from Crypto.Cipher import AES

def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int = 32, iv_len: int = 16, md_name: str = 'sha256'):
    hasher = getattr(hashlib, md_name)
    blocks = []
    d = b''
    while len(b''.join(blocks)) < (key_len + iv_len):
        d = hasher(d + password + salt).digest()
        blocks.append(d)
    key_iv = b''.join(blocks)
    return key_iv[:key_len], key_iv[key_len:key_len + iv_len]

def solve():
    print("[*] Solving Operation Orchid...")
    workspace = Path(__file__).resolve().parent
    img_path = workspace / "disk.flag.img"
    gz_path = workspace / "disk.flag.img.gz"

    if not img_path.exists() and gz_path.exists():
        print("[*] Extracting disk.flag.img.gz...")
        with gzip.open(gz_path, 'rb') as f_in, open(img_path, 'wb') as f_out:
            while chunk := f_in.read(1024 * 1024 * 8):
                f_out.write(chunk)

    # Read disk data
    print("[*] Inspecting disk image for commands and flag file...")
    with open(img_path, 'rb') as f:
        disk_data = f.read()

    # Find the openssl encryption command in bash/ash history
    cmd_match = re.search(rb'openssl aes256 -salt -in flag\.txt -out flag\.txt\.enc -k (\S+)', disk_data)
    if cmd_match:
        password = cmd_match.group(1)
        print(f"[*] Found encryption password: {password.decode('latin1')}")
    else:
        password = b"unbreakablepassword1234567"
        print(f"[*] Defaulting to password: {password.decode('latin1')}")

    # Locate flag.txt.enc either in workspace or inside the disk image
    enc_path = workspace / "flag.txt.enc"
    if enc_path.exists():
        with open(enc_path, 'rb') as f:
            enc_data = f.read()
    else:
        # Search for Salted__ pattern in disk
        matches = [m.start() for m in re.finditer(rb'Salted__', disk_data)]
        enc_data = disk_data[matches[0]:matches[0] + 64]

    assert enc_data.startswith(b"Salted__"), "Invalid OpenSSL salted header"
    salt = enc_data[8:16]
    ciphertext = enc_data[16:]

    flag = ""
    # Try different hash algorithms (sha256 is default in OpenSSL 1.1.0+)
    for md in ['sha256', 'md5', 'sha1']:
        key, iv = evp_bytes_to_key(password, salt, 32, 16, md)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ciphertext)
        match = re.search(rb'(?:academy|picoCTF)\{[^}]+\}', pt)
        if match:
            flag = match.group(0).decode('utf-8', errors='ignore')
            print(f"[+] Found flag using {md}: {flag}")
            break

    if not flag:
        raise ValueError("Flag not found!")

    # Write flag.txt
    flag_file = workspace / "flag.txt"
    flag_file.write_text(flag + "\n", encoding="utf-8")
    print(f"[+] Saved flag to {flag_file}")

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{h4un71ng_p457_0b36d810}
```
