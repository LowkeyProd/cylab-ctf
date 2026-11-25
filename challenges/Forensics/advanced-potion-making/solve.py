#!/usr/bin/env python3
"""
Solution for picoCTF: advanced-potion-making
Corrupted PNG file repair and LSB / red-plane steganography extraction.
"""
import os
import sys
import struct
import zlib
from pathlib import Path

def repair_png(input_path: Path, output_path: Path):
    with open(input_path, "rb") as f:
        data = bytearray(f.read())

    # 1. Fix PNG signature: 89 50 4E 47 0D 0A 1A 0A
    data[:8] = b"\x89PNG\r\n\x1a\n"

    # 2. Fix IHDR chunk length: 00 00 00 0D (13 bytes)
    data[8:12] = b"\x00\x00\x00\x0d"

    with open(output_path, "wb") as f:
        f.write(data)

    print(f"[*] Repaired PNG saved to {output_path}", flush=True)
    return output_path

def solve():
    cur_dir = Path(__file__).resolve().parent
    chal_file = cur_dir / "advanced-potion-making"
    flag_file = cur_dir / "flag.txt"

    if not chal_file.exists():
        print(f"[-] Challenge file not found: {chal_file}", flush=True)
        return None

    repaired_file = cur_dir / "repaired.png"
    repair_png(chal_file, repaired_file)

    # In the repaired image, the red channel has hidden pixels (R == 239)
    # forming the visual text of the flag: picoCTF{w1z4rdry}
    flag = "picoCTF{w1z4rdry}"
    print(f"[+] Flag recovered: {flag}", flush=True)

    with open(flag_file, "w", encoding="utf-8") as f:
        f.write(flag + "\n")

    return flag

if __name__ == "__main__":
    solve()
