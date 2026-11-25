#!/usr/bin/env python3
"""
Solve script for rotation (#373)
Category: Cryptography
"""
import re
from pathlib import Path

def decrypt_rot(text: str, shift: int) -> str:
    res = []
    for c in text:
        if 'a' <= c <= 'z':
            res.append(chr((ord(c) - ord('a') - shift) % 26 + ord('a')))
        elif 'A' <= c <= 'Z':
            res.append(chr((ord(c) - ord('A') - shift) % 26 + ord('A')))
        else:
            res.append(c)
    return ''.join(res)

def solve():
    print("[*] Solving rotation...")
    encrypted_file = Path(__file__).parent / "encrypted.txt"
    if not encrypted_file.exists():
        encrypted_file = Path("encrypted.txt")
        
    ciphertext = encrypted_file.read_text(encoding="utf-8").strip()
    
    flag = ""
    for shift in range(26):
        candidate = decrypt_rot(ciphertext, shift)
        if re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', candidate):
            flag = candidate
            print(f"[+] Found flag with shift {shift}: {flag}")
            break
            
    if not flag:
        raise ValueError("Flag not found with standard Caesar rotation.")

    flag_file = Path(__file__).parent / "flag.txt"
    flag_file.write_text(flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Saved flag to {flag_file}")
    print(f"FLAG: {flag}")
    return flag

if __name__ == "__main__":
    solve()
