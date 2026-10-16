#!/usr/bin/env python3
"""
Solve script for WhitePages (Forensics)
Extracts hidden binary data encoded with Unicode EM Space (U+2003) and ASCII Space (U+0020).
"""
import os
import re
import sys

def solve():
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "whitepages.txt")
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found!", file=sys.stderr)
        sys.exit(1)

    with open(file_path, "rb") as f:
        data = f.read()

    # EM SPACE (U+2003) in UTF-8 is \xe2\x80\x83 -> '0'
    # ASCII SPACE (U+0020) is \x20 -> '1'
    bit_data = data.replace(b"\xe2\x80\x83", b"0").replace(b" ", b"1")
    bits = [chr(c) for c in bit_data if c in (ord('0'), ord('1'))]
    bitstring = "".join(bits)

    decoded_bytes = bytearray()
    for i in range(0, len(bitstring), 8):
        byte_chunk = bitstring[i:i+8]
        if len(byte_chunk) == 8:
            decoded_bytes.append(int(byte_chunk, 2))

    decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
    
    match = re.search(r"(?:academy|picoCTF)\{[^}]+\}", decoded_text)
    if not match:
        print("[-] Flag not found in decoded text!", file=sys.stderr)
        sys.exit(1)

    flag = match.group(0)
    print(f"[+] Flag found: {flag}")

    flag_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flag.txt")
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag + "\n")

    return flag

if __name__ == "__main__":
    solve()
