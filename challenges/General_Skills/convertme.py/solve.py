#!/usr/bin/env python3
"""
Solve script for convertme.py (#239)
Category: General Skills
"""
from pathlib import Path
import re

def str_xor(secret, key):
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])

def solve():
    print("[*] Solving convertme.py...", flush=True)
    flag_enc = chr(0x04) + chr(0x0d) + chr(0x0a) + chr(0x0d) + chr(0x01) + chr(0x18) + chr(0x1c) + chr(0x15) + chr(0x5f) + chr(0x05) + chr(0x08) + chr(0x2a) + chr(0x1c) + chr(0x5e) + chr(0x1e) + chr(0x1b) + chr(0x3b) + chr(0x17) + chr(0x51) + chr(0x5b) + chr(0x58) + chr(0x5c) + chr(0x3b) + chr(0x40) + chr(0x01) + chr(0x0c) + chr(0x08) + chr(0x5e) + chr(0x00) + chr(0x4c) + chr(0x53) + chr(0x13)
    flag = str_xor(flag_enc, 'enkidu')
    print(f"[+] Flag found: {flag}", flush=True)

    # Save to flag.txt
    Path("flag.txt").write_text(flag.strip())
    print("[+] Flag saved to flag.txt", flush=True)
    return flag

if __name__ == "__main__":
    solve()
