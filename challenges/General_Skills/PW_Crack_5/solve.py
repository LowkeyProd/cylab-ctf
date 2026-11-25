#!/usr/bin/env python3
"""
Solve script for PW Crack 5 (#249)
Category: General Skills
"""
import hashlib
from pathlib import Path

def str_xor(secret, key):
    # extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])

def solve():
    print("[*] Solving PW Crack 5...")
    base_dir = Path(__file__).parent
    flag_enc = (base_dir / 'level5.flag.txt.enc').read_bytes().decode('latin1', errors='ignore')
    correct_pw_hash = (base_dir / 'level5.hash.bin').read_bytes()

    dict_path = base_dir / 'dictionary.txt'
    with open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            pw = line.strip()
            if hashlib.md5(pw.encode()).digest() == correct_pw_hash:
                print(f"[+] Found password: {pw}")
                flag = str_xor(flag_enc, pw)
                print(f"[+] Flag: {flag}")
                (base_dir / 'flag.txt').write_text(flag.strip())
                return flag

    print("[-] Password not found!")
    return None

if __name__ == "__main__":
    solve()
