#!/usr/bin/env python3
"""
Solve script for Investigative Reversing 4 (#54)
Extracts the flag encoded in Item05_cp.bmp through Item01_cp.bmp.
"""
import os

def solve():
    files = [
        "Item05_cp.bmp",
        "Item04_cp.bmp",
        "Item03_cp.bmp",
        "Item02_cp.bmp",
        "Item01_cp.bmp",
    ]
    
    flag_chars = []
    for fname in files:
        if not os.path.exists(fname):
            raise FileNotFoundError(f"Missing file: {fname}")
        with open(fname, "rb") as f:
            data = f.read()
        
        offset = 2019
        for c in range(10):
            char_val = 0
            for bit in range(8):
                b = data[offset + c * 12 + bit]
                char_val |= ((b & 1) << bit)
            flag_chars.append(chr(char_val))
    
    flag = "".join(flag_chars)
    print(f"Flag extracted: {flag}", flush=True)
    
    with open("flag.txt", "w") as f:
        f.write(flag)
    
    return flag

if __name__ == "__main__":
    solve()
