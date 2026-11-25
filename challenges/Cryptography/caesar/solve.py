#!/usr/bin/env python3
"""
Solve script for caesar (#64)
Category: Cryptography
"""
import sys
from pathlib import Path

def solve():
    print("[*] Solving caesar...", flush=True)
    enc_path = Path(__file__).parent / "data.enc"
    with open(enc_path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    # The format is academy{...}
    prefix = content[:content.index("{") + 1]
    suffix = content[content.index("}"):]
    ciphertext = content[content.index("{") + 1:content.index("}")]

    shift = 21
    decrypted_inner = "".join(
        chr((ord(c) - ord('a') - shift) % 26 + ord('a')) if 'a' <= c <= 'z' else c
        for c in ciphertext
    )

    flag = f"{prefix}{decrypted_inner}{suffix}"
    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = Path(__file__).parent / "flag.txt"
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag + "\n")

    return flag

if __name__ == "__main__":
    solve()
