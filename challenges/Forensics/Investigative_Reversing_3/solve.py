#!/usr/bin/env python3
"""
Solve script for Investigative Reversing 3 (#83)
Category: Forensics
"""
from pathlib import Path
import re

def solve():
    print("[*] Solving Investigative Reversing 3...", flush=True)

    bmp_path = Path("investigative-reversing-3-encoded.bmp")
    if not bmp_path.exists():
        print("[-] Encoded BMP file not found!", flush=True)
        return ""

    with open(bmp_path, "rb") as f:
        data = f.read()

    # The mystery binary copies 0x2d3 (723) bytes from original.bmp to encoded.bmp.
    # Then for each of the 50 flag characters:
    # - 8 bits (LSB to MSB) are embedded into the LSB of 8 consecutive bytes in encoded.bmp.
    # - 1 byte is copied verbatim from original.bmp without modification.
    # Thus, character c is encoded across bytes at offsets: 723 + c * 9 + j (for j = 0..7).

    flag_chars = []
    for c in range(50):
        start = 723 + c * 9
        byte_val = 0
        for j in range(8):
            bit = data[start + j] & 1
            byte_val |= (bit << j)
        flag_chars.append(chr(byte_val))

    extracted = "".join(flag_chars)

    # Validate flag pattern
    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", extracted)
    if match:
        flag = match.group(1)
    else:
        flag = extracted

    print(f"[+] Extracted flag: {flag}", flush=True)

    with open("flag.txt", "w") as f:
        f.write(flag)

    return flag

if __name__ == "__main__":
    solve()
