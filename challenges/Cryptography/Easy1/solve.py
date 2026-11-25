#!/usr/bin/env python3
"""
Solve script for Easy1 (#43)
Category: Cryptography
"""
import sys
from pathlib import Path

def parse_connection_cfg():
    cfg = {}
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg

def decrypt_vigenere(ciphertext: str, key: str) -> str:
    plaintext = []
    for c, k in zip(ciphertext, key):
        c_val = ord(c) - ord('A')
        k_val = ord(k) - ord('A')
        p_val = (c_val - k_val) % 26
        plaintext.append(chr(p_val + ord('A')))
    return "".join(plaintext)

def solve():
    cfg = parse_connection_cfg()
    print(f"[*] Loaded config: {cfg}", flush=True)

    ciphertext = "UFJKXQZQUNB"
    key = "SOLVECRYPTO"

    decrypted = decrypt_vigenere(ciphertext, key)
    print(f"[+] Decrypted text: {decrypted}", flush=True)

    flag = f"academy{{{decrypted}}}"
    print(f"[+] Flag: {flag}", flush=True)

    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Flag successfully saved to {flag_file}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
