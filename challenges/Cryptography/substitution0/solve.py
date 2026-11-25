#!/usr/bin/env python3
"""
Solve script for substitution0 (#307)
Category: Cryptography
"""
import re
import string
from pathlib import Path

def solve():
    print("[*] Solving substitution0...", flush=True)
    msg_path = Path(__file__).parent / "message.txt"
    with open(msg_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    key = lines[0].strip()
    ciphertext = "".join(lines[1:])
    
    # Key mapping: key[i] corresponds to string.ascii_uppercase[i]
    # For decryption, ciphertext char c (at key.index(c)) -> string.ascii_uppercase[key.index(c)]
    upper_map = {k: v for k, v in zip(key, string.ascii_uppercase)}
    lower_map = {k.lower(): v.lower() for k, v in zip(key, string.ascii_uppercase)}
    
    decrypted_chars = []
    for c in ciphertext:
        if c in upper_map:
            decrypted_chars.append(upper_map[c])
        elif c in lower_map:
            decrypted_chars.append(lower_map[c])
        else:
            decrypted_chars.append(c)
            
    decrypted_text = "".join(decrypted_chars)
    print("\nDecrypted message sample:\n", flush=True)
    print(decrypted_text[:300], flush=True)
    print("...\n", flush=True)
    
    # Match flag
    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", decrypted_text)
    if not match:
        raise ValueError("Flag not found in decrypted text!")
    
    flag = match.group(1)
    print(f"[+] Flag found: {flag}", flush=True)
    
    flag_path = Path(__file__).parent / "flag.txt"
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag)
    print(f"[+] Saved flag to {flag_path}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
