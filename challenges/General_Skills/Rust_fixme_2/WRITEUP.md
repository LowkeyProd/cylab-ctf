# Writeup: Rust fixme 2

## Header & Metadata
- **Challenge:** Rust fixme 2 (ID: 462)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** fixme2.tar.gz
- **Official Flag:** `academy{4r3_y0u_h4v1n5_fun_y31?}`

---

## Mô tả bài toán (Overview / Analysis)
The Rust saga continues? I ask you, can I borrow that, pleeeeeaaaasseeeee?

Download the Rust code <a href='https://challenge-files.cylabacademy.net/library/048c73621a97b98cde18eae5a9495279f2396cb64c65235bb310e7ad26d726ac/fixme2.tar.gz' download>here</a>.


### Hints
- https://doc.rust-lang.org/book/ch04-02-references-and-borrowing.html

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solver for Rust fixme 2 (#462)
Category: General Skills
"""

import math
import re
import struct
import sys
from pathlib import Path

def parse_connection_cfg(cfg_path: Path):
    config = {}
    if cfg_path.exists():
        for line in cfg_path.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def generate_tables():
    e_table = [0] * 256
    d_table = [0] * 0xF10
    for i in range(256):
        count = 4
        shift = 0
        value = i
        mask = 0
        mode = 0
        while count != 0:
            bit_mask = value & 3
            mask_shift = 1 if bit_mask > 1 else 0
            mode_shift = 1 if (bit_mask == 0 or bit_mask == 3) else 0
            mask |= (mask_shift << shift)
            mode |= (mode_shift << shift)
            count -= 1
            shift += 1
            value >>= 2
        mask = (mode << 8) | mask
        e_table[i] = mask
        d_table[mask] = i
    return e_table, d_table

def generate_mask(v: int) -> int:
    mask = 0x0101010101010101
    vt = v
    shift = 8
    bv = 0
    bz = 0x0808080808080808
    while shift != 0:
        bm = mask & vt
        bv = (bv + bm) & 0xFFFFFFFFFFFFFFFF
        bz = (bz - bm) & 0xFFFFFFFFFFFFFFFF
        vt >>= 1
        shift -= 1
    return (((bz << 4) & 0xFFFFFFFFFFFFFFFF | bv) ^ ((bv << 4) & 0xFFFFFFFFFFFFFFFF | bz) ^ v) & 0xFFFFFFFFFFFFFFFF

def get_ciphers(key: bytes) -> list:
    g = math.gcd(len(key), 8)
    rep = (len(key) // g) * 8
    data = (key * (rep // len(key) + 1))[:rep]
    ciphers = list(struct.unpack('<' + 'Q' * (rep // 8), data))
    for i in range(len(ciphers)):
        ciphers[i] = generate_mask(ciphers[i])
    return ciphers

def decrypt_byte(val: int, d_table: list) -> int:
    return (d_table[val & 0x0F0F]
        | (d_table[(val >> 0x4) & 0x0F0F] << 0x8)
        | (d_table[(val >> 0x10) & 0x0F0F] << 0x10)
        | (d_table[(val >> 0x14) & 0x0F0F] << 0x18)
        | (d_table[(val >> 0x20) & 0x0F0F] << 0x20)
        | (d_table[(val >> 0x24) & 0x0F0F] << 0x28)
        | (d_table[(val >> 0x30) & 0x0F0F] << 0x30)
        | (d_table[(val >> 0x34) & 0x0F0F] << 0x38))

def decrypt_v1(encrypted_bytes: bytes, key: bytes) -> bytes:
    _, d_table = generate_tables()
    ciphers = get_ciphers(key)

    b_len = len(encrypted_bytes)
    odd = (b_len % 8 != 0)
    num_words = b_len // 8
    words = list(struct.unpack(f'<{num_words}Q', encrypted_bytes[:num_words * 8]))

    decrypted_words = []
    for i in range(num_words):
        val = words[i] ^ ciphers[i % len(ciphers)]
        xi = (((val & 0x00FF00FF00FF00FF) << 8) ^ val) & 0xFFFFFFFFFFFFFFFF
        dec = decrypt_byte(xi, d_table)
        decrypted_words.append(dec)

    out = bytearray(struct.pack(f'<{num_words}Q', *decrypted_words))

    if odd:
        rem_bytes = encrypted_bytes[num_words * 8:]
        val = int.from_bytes(rem_bytes, 'little')
        val ^= ciphers[num_words % len(ciphers)]
        xi = (((val & 0x00FF00FF00FF00FF) << 8) ^ val) & 0xFFFFFFFFFFFFFFFF
        byte_count = len(rem_bytes)
        lxi = 0
        shift = 0
        while byte_count > 1:
            lxi |= (d_table[(xi >> shift) & 0x0F0F] << shift) | (d_table[(xi >> shift >> 4) & 0x0F0F] << (8 + shift))
            shift += 0x10
            byte_count -= 2
        mm = (xi >> shift) & 0xFF
        mm ^= (mm >> 4)
        mm = ((mm & 0xF0) >> 4) | ((mm & 0xF) << 8)
        lxi |= (d_table[mm] << shift)
        out.extend(lxi.to_bytes(8, 'little')[:len(rem_bytes)])

    return bytes(out)

def solve():
    base_dir = Path(__file__).resolve().parent
    cfg = parse_connection_cfg(base_dir / "connection.cfg")
    print(f"[*] Loaded configuration: {cfg}", flush=True)

    main_rs_path = base_dir / "fixme2" / "src" / "main.rs"
    if not main_rs_path.exists():
        print(f"[-] Could not find {main_rs_path}", flush=True)
        return

    content = main_rs_path.read_text()

    # Extract key
    key_match = re.search(r'let\s+key\s*=\s*String::from\("([^"]+)"\);', content)
    key_str = key_match.group(1) if key_match else "CSUCKS"
    key = key_str.encode("utf-8")
    print(f"[*] Key: {key_str}", flush=True)

    # Extract hex values
    hex_match = re.search(r'let\s+hex_values\s*=\s*\[(.*?)\];', content, re.DOTALL)
    if not hex_match:
        print("[-] Could not find hex_values in main.rs", flush=True)
        return

    hex_tokens = re.findall(r'"([0-9a-fA-F]{1,2})"', hex_match.group(1))
    encrypted_bytes = bytes([int(x, 16) for x in hex_tokens])
    print(f"[*] Extracted {len(encrypted_bytes)} encrypted bytes", flush=True)

    decrypted = decrypt_v1(encrypted_bytes, key)
    decrypted_str = decrypted.decode("utf-8", errors="replace")
    print(f"[*] Decrypted string: {decrypted_str}", flush=True)

    flag_match = re.search(r'(?:academy|picoCTF)\{[^}]+\}', decrypted_str)
    if flag_match:
        flag = flag_match.group(0)
        print(f"[+] Flag found: {flag}", flush=True)
        (base_dir / "flag.txt").write_text(flag + "\n")
        return flag
    else:
        print("[-] Flag pattern not found in decrypted string", flush=True)
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{4r3_y0u_h4v1n5_fun_y31?}
```
