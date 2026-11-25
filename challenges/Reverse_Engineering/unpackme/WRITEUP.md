# Writeup: unpackme

## Header & Metadata
- **Challenge:** unpackme (ID: 313)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `https://challenge-files.cylabacademy.net/library/0073cc3d5de6cce918ad71857941f85a1cab2e97148a498ef1a46fa7fa348879/unpackme-upx`
- **Attached Files:** unpackme-upx
- **Official Flag:** `academy{up><_m3_f7w_66947202}`

---

## Mô tả bài toán (Overview / Analysis)
Can you get the flag?
Reverse engineer this <a href='https://challenge-files.cylabacademy.net/library/0073cc3d5de6cce918ad71857941f85a1cab2e97148a498ef1a46fa7fa348879/unpackme-upx' download>binary</a>.

### Hints
- What is UPX?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Self-contained solver script for 'unpackme' (#313).
Reconstructs the ROT47 algorithm and stack buffer decoding logic.
"""
import sys
import struct
import re
from pathlib import Path

def rot47(s: str) -> str:
    """Implements ROT47 cipher as found in rotate_encrypt."""
    out = []
    for c in s:
        v = ord(c)
        if 33 <= v <= 126:
            out.append(chr(33 + ((v - 33 + 47) % 94)))
        else:
            out.append(c)
    return "".join(out)

def decode_embedded_flag() -> str:
    """
    Reconstructs the stack memory buffer created in main (0x401a23):
    - [rbp-0x30] = 0x4c4a3e3635323432 (offset 0)
    - [rbp-0x28] = 0x30623e306b6d4146 (offset 8)
    - [rbp-0x22] = 0x6565304866373062 (offset 14)
    - [rbp-0x1a] = 0x004e615f61666368 (offset 22)
    """
    buf = bytearray(32)
    buf[0:8] = struct.pack("<Q", 0x4c4a3e3635323432)
    buf[8:16] = struct.pack("<Q", 0x30623e306b6d4146)
    buf[14:22] = struct.pack("<Q", 0x6565304866373062)
    buf[22:30] = struct.pack("<Q", 0x004e615f61666368)

    encoded_str = buf.split(b"\x00")[0].decode("latin1")
    print(f"[*] Reconstructed ciphertext: {encoded_str}", flush=True)

    flag = rot47(encoded_str)
    return flag

def main():
    print("[*] Starting unpackme solver...", flush=True)
    flag = decode_embedded_flag()
    print(f"[+] Decoded candidate: {flag}", flush=True)

    match = re.search(r"(?:academy|picoCTF)\{[^}]+\}", flag)
    if not match:
        print("[-] Flag verification failed: format does not match.", flush=True)
        sys.exit(1)

    exact_flag = match.group(0)
    print(f"[+] Verified Flag: {exact_flag}", flush=True)

    flag_path = Path(__file__).resolve().parent / "flag.txt"
    flag_path.write_text(exact_flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Saved flag to {flag_path.name}", flush=True)

if __name__ == "__main__":
    main()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{up><_m3_f7w_66947202}
```
