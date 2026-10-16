#!/usr/bin/env python3
"""
Solver for picoCTF - Investigative Reversing 2
Challenge folder: cylab/Investigative Reversing 2 - hard

Mechanism:
1. The binary copies the first 2000 bytes (0x7D0) of original.bmp unchanged to encoded.bmp.
2. For each of the 50 characters of flag.txt:
   - Each character is subtracted by 5: `encoded_char = flag[i] - 5`
   - Each bit (from bit 0 to bit 7) is embedded into the LSB of consecutive bytes of the BMP.
3. Total encoded bytes = 50 * 8 = 400 bytes, starting at offset 2000.
4. To reverse:
   - Read 8 bytes for each character starting at byte offset 2000.
   - Extract LSB: `bit = byte & 1`.
   - Reconstruct byte: `val = sum(bit << b for b in range(8))`.
   - Reconstruct original char: `flag[i] = chr(val + 5)`.
"""

import sys
import os

BMP_FILE = os.path.join(os.path.dirname(__file__), "encoded.bmp")

def solve(bmp_path=BMP_FILE):
    if not os.path.exists(bmp_path):
        print(f"[-] File not found: {bmp_path}")
        return None

    with open(bmp_path, "rb") as f:
        data = f.read()

    start_offset = 2000
    flag_len = 50
    flag_chars = []

    for i in range(flag_len):
        char_val = 0
        for b in range(8):
            byte_idx = start_offset + (i * 8) + b
            bit = data[byte_idx] & 1
            char_val |= (bit << b)
        
        orig_char = (char_val + 5) & 0xff
        flag_chars.append(chr(orig_char))

    flag = "".join(flag_chars)
    return flag

if __name__ == "__main__":
    flag = solve()
    print(f"[+] Flag found: {flag}")
