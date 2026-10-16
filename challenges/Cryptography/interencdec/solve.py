#!/usr/bin/env python3
"""
Solve script for interencdec (#418)
Category: Cryptography
Method: Multi-stage decoding (Base64 -> Base64 -> Caesar Cipher shift of 7)
"""
import base64
import re
from pathlib import Path

def solve():
    enc_flag_path = Path(__file__).resolve().parent / "enc_flag"
    with open(enc_flag_path, "r") as f:
        content = f.read().strip()

    print(f"[*] Raw input: {content}")

    # Stage 1: Base64 decode
    d1 = base64.b64decode(content).decode()
    print(f"[*] Stage 1 (Base64 decoded): {d1}")

    # Stage 2: Extract inner base64 string and decode
    inner_m = re.findall(r"['\"]([^'\"]+)['\"]", d1)
    inner = inner_m[0] if inner_m else d1
    d2 = base64.b64decode(inner).decode()
    print(f"[*] Stage 2 (Inner Base64 decoded): {d2}")

    # Stage 3: Caesar cipher decode (shift 7)
    shift = 7
    flag = ""
    for ch in d2:
        if 'a' <= ch <= 'z':
            flag += chr((ord(ch) - ord('a') - shift) % 26 + ord('a'))
        elif 'A' <= ch <= 'Z':
            flag += chr((ord(ch) - ord('A') - shift) % 26 + ord('A'))
        else:
            flag += ch

    print(f"[+] Decrypted Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
