#!/usr/bin/env python3
"""
Solve script for PW Crack 3 (#247)
Category: General Skills
"""
import hashlib
from pathlib import Path

def str_xor(secret, key):
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])

def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()

def solve():
    print("[*] Solving PW Crack 3...")
    base_dir = Path(__file__).resolve().parent
    flag_enc = (base_dir / "level3.flag.txt.enc").read_bytes()
    correct_pw_hash = (base_dir / "level3.hash.bin").read_bytes()

    pos_pw_list = ["f09e", "4dcf", "87ab", "dba8", "752e", "3961", "f159"]
    
    flag = ""
    for pw in pos_pw_list:
        if hash_pw(pw) == correct_pw_hash:
            print(f"[+] Found correct password: {pw}")
            flag = str_xor(flag_enc.decode(), pw).strip()
            break

    if not flag:
        raise ValueError("Password not found among candidate list!")

    print(f"[+] Flag found: {flag}")
    (base_dir / "flag.txt").write_text(flag + "\n", encoding="utf-8")
    return flag

if __name__ == "__main__":
    solve()
