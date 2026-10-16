#!/usr/bin/env python3
"""
Solve script for Investigative Reversing 0 (#70)
Category: Forensics / Reverse Engineering
"""

import os
import sys

def solve():
    png_path = os.path.join(os.path.dirname(__file__), "investigative-reversing-0-mystery.png")
    
    with open(png_path, "rb") as f:
        data = f.read()
    
    # Locate PNG IEND chunk
    # PNG structure ends with IEND chunk: length (4 bytes: 00 00 00 00) + type (4 bytes: 'IEND') + CRC (4 bytes)
    iend_pos = data.find(b"IEND")
    if iend_pos == -1:
        raise ValueError("IEND chunk not found in PNG file.")
    
    # Trailing data appended after PNG IEND chunk CRC (4 bytes for 'IEND' + 4 bytes CRC = 8 bytes)
    trailing_data = data[iend_pos + 8:]
    if len(trailing_data) < 26:
        raise ValueError(f"Expected at least 26 bytes of appended data, got {len(trailing_data)}")
    
    encoded_flag = trailing_data[:26]
    flag_chars = []
    
    # Reverse the transformations observed in the binary's main function:
    # 1. bytes 0..5: unchanged
    # 2. bytes 6..14: encoded = orig + 5  => orig = encoded - 5
    # 3. byte 15: encoded = orig - 3      => orig = encoded + 3
    # 4. bytes 16..25: unchanged
    for i, b in enumerate(encoded_flag):
        if i < 6:
            flag_chars.append(chr(b))
        elif 6 <= i <= 14:
            flag_chars.append(chr(b - 5))
        elif i == 15:
            flag_chars.append(chr(b + 3))
        else: # 16 <= i <= 25
            flag_chars.append(chr(b))
            
    flag = "".join(flag_chars)
    print(flag)
    
    flag_path = os.path.join(os.path.dirname(__file__), "flag.txt")
    with open(flag_path, "w") as f:
        f.write(flag + "\n")

if __name__ == "__main__":
    solve()
