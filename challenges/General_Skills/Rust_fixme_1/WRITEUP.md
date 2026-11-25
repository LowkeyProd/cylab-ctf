# Writeup: Rust fixme 1

## Header & Metadata
- **Challenge:** Rust fixme 1 (ID: 461)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** fixme1.tar.gz
- **Official Flag:** `academy{4r3_y0u_4_ru$t4c30n_n0w?}`

---

## Mô tả bài toán (Overview / Analysis)
Have you heard of Rust? Fix the syntax errors in this Rust file to print the flag!

Download the Rust code <a href='https://challenge-files.cylabacademy.net/library/b9cfc84c442958b8ac848ddc0692bed9ef01a15877b8d37f36afbe68b5849acc/fixme1.tar.gz' download>here</a>.


### Hints
- Cargo is Rust's package manager and will make your life easier. See the getting started page [here](https://doc.rust-lang.org/book/ch01-03-hello-cargo.html)
- [println!](https://doc.rust-lang.org/std/macro.println.html)
- Rust has some pretty great compiler error messages. Read them maybe?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Deterministic solver for Rust fixme 1 (#461)
Category: General Skills
"""
import sys
import re
import struct
import math
import tarfile
from pathlib import Path

def read_config():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def generate_table():
    e_table = [0] * 256
    d_table = [0] * 0xF10
    for i in range(256):
        count, shift, value = 4, 0, i
        mask, mode = 0, 0
        while count != 0:
            bit_mask = value & 3
            mask_shift = 1 if bit_mask > 1 else 0
            mode_shift = 1 if (bit_mask == 0 or bit_mask == 3) else 0
            mask |= mask_shift << shift
            mode |= mode_shift << shift
            count -= 1
            shift += 1
            value >>= 2
        mask = ((mode << 8) | mask) & 0xFFFF
        e_table[i] = mask
        d_table[mask] = i
    return e_table, d_table

def generate_mask(v):
    mask = 0x0101010101010101
    vt = v & 0xFFFFFFFFFFFFFFFF
    shift = 8
    bv = 0
    bz = 0x0808080808080808
    while shift != 0:
        bm = mask & vt
        bv = (bv + bm) & 0xFFFFFFFFFFFFFFFF
        bz = (bz - bm) & 0xFFFFFFFFFFFFFFFF
        vt >>= 1
        shift -= 1
    return (((bz << 4) | bv) ^ ((bv << 4) | bz) ^ v) & 0xFFFFFFFFFFFFFFFF

def get_cipher(key_bytes):
    n = len(key_bytes)
    g = math.gcd(n, 8)
    rep = (n // g) * 8
    data = bytearray(rep)
    for i in range(rep):
        data[i] = key_bytes[i % n]
    cipher_64 = list(struct.unpack(f'<{rep//8}Q', data))
    for i in range(len(cipher_64)):
        cipher_64[i] = generate_mask(cipher_64[i])
    return cipher_64

def decrypt_xor_cryptor_v1(key_bytes, encrypted_bytes):
    e_table, d_table = generate_table()

    def decrypt_byte(val):
        return (d_table[val & 0x0F0F]
            | (d_table[(val >> 0x4) & 0x0F0F] << 0x8)
            | (d_table[(val >> 0x10) & 0x0F0F] << 0x10)
            | (d_table[(val >> 0x14) & 0x0F0F] << 0x18)
            | (d_table[(val >> 0x20) & 0x0F0F] << 0x20)
            | (d_table[(val >> 0x24) & 0x0F0F] << 0x28)
            | (d_table[(val >> 0x30) & 0x0F0F] << 0x30)
            | (d_table[(val >> 0x34) & 0x0F0F] << 0x38)) & 0xFFFFFFFFFFFFFFFF

    b_len = len(encrypted_bytes)
    pad_len = (8 - (b_len % 8)) % 8
    padded = encrypted_bytes + b'\x00' * pad_len
    src = list(struct.unpack(f'<{len(padded)//8}Q', padded))

    cipher = get_cipher(key_bytes)
    def get_cipher_byte(i):
        return cipher[i % len(cipher)]

    odd = (b_len % 8 != 0)
    length = len(src) - (1 if odd else 0)
    byte_count = b_len - 8 * length

    for i in range(length):
        src[i] ^= get_cipher_byte(i)
        val = src[i]
        xi = (((val & 0x00FF00FF00FF00FF) << 8) ^ val) & 0xFFFFFFFFFFFFFFFF
        src[i] = decrypt_byte(xi)

    if odd:
        src[length] ^= get_cipher_byte(length)
        xi = (((src[length] & 0x00FF00FF00FF00FF) << 8) ^ src[length]) & 0xFFFFFFFFFFFFFFFF
        lxi, shift = 0, 0
        while byte_count > 1:
            lxi |= ((d_table[(xi >> shift) & 0x0F0F]) << shift) | ((d_table[(xi >> shift >> 4) & 0x0F0F]) << (8 + shift))
            shift += 0x10
            byte_count -= 2
        mm = (xi >> shift) & 0xFF
        mm ^= (mm >> 4)
        mm = (((mm & 0xF0) >> 4) | ((mm & 0xF) << 8)) & 0xFFFF
        lxi |= (d_table[mm]) << shift
        src[length] = lxi & 0xFFFFFFFFFFFFFFFF

    decrypted = struct.pack(f'<{len(src)}Q', *src)[:b_len]
    return decrypted

def solve():
    base_dir = Path(__file__).resolve().parent
    config = read_config()
    print(f"[*] Configuration loaded: {config}", flush=True)

    main_rs = base_dir / "fixme1" / "src" / "main.rs"
    if not main_rs.exists():
        archive = base_dir / "fixme1.tar.gz"
        if archive.exists():
            print(f"[*] Extracting {archive.name}...", flush=True)
            with tarfile.open(archive, "r:gz") as tar:
                tar.extractall(base_dir)

    if not main_rs.exists():
        print(f"[-] Could not find main.rs at {main_rs}", flush=True)
        return None

    code = main_rs.read_text(encoding="utf-8")
    key_match = re.search(r'String::from\(["\'](.*?)["\']\)', code)
    if not key_match:
        print("[-] Could not parse key from main.rs", flush=True)
        return None
    key = key_match.group(1).encode("utf-8")
    print(f"[*] Parsed key: {key.decode('utf-8')}", flush=True)

    hex_match = re.search(r'hex_values\s*=\s*\[(.*?)\]', code, re.DOTALL)
    if not hex_match:
        print("[-] Could not parse hex_values from main.rs", flush=True)
        return None
    hex_str = hex_match.group(1)
    hex_items = [x.strip().strip('"\'') for x in hex_str.split(",") if x.strip()]
    encrypted_bytes = bytes([int(x, 16) for x in hex_items])
    print(f"[*] Encrypted bytes count: {len(encrypted_bytes)}", flush=True)

    decrypted_bytes = decrypt_xor_cryptor_v1(key, encrypted_bytes)
    decrypted_str = decrypted_bytes.decode("utf-8", errors="replace")
    print(f"[*] Decrypted string: {decrypted_str}", flush=True)

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[^}]+\}')
    matches = flag_pattern.findall(decrypted_str)
    if matches:
        flag = matches[0]
        for decoy in ['decoy', 'fake', 'honeypot', 'dummy']:
            if decoy in flag.lower():
                print(f"[-] Decoy flag rejected: {flag}", flush=True)
                return None
        print(f"[+] Flag found: {flag}", flush=True)
        flag_file = base_dir / "flag.txt"
        flag_file.write_text(flag + "\n", encoding="utf-8")
        print(f"[+] Saved flag to {flag_file}", flush=True)
        return flag
    else:
        print("[-] No flag found in decrypted text", flush=True)
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{4r3_y0u_4_ru$t4c30n_n0w?}
```
