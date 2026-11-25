#!/usr/bin/env python3
"""
Solve script for Vigenere (#316)
Category: Cryptography
"""
from pathlib import Path

def decrypt_vigenere(ciphertext: str, key: str) -> str:
    plaintext = []
    key_idx = 0
    key = key.upper()
    for ch in ciphertext:
        if ch.isupper():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            plaintext.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
            key_idx += 1
        elif ch.islower():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            plaintext.append(chr((ord(ch) - ord('a') - shift) % 26 + ord('a')))
            key_idx += 1
        else:
            plaintext.append(ch)
    return "".join(plaintext)

def solve():
    print("[*] Solving Vigenere...")
    cipher_file = Path(__file__).parent / "cipher.txt"
    if cipher_file.exists():
        ciphertext = cipher_file.read_text().strip()
    else:
        raise FileNotFoundError("cipher.txt not found")

    flag = decrypt_vigenere(ciphertext, "CYLAB")
    print(f"[+] Decrypted flag: {flag}")

    flag_file = Path(__file__).parent / "flag.txt"
    flag_file.write_text(flag + "\n")
    print(f"[+] Flag written to {flag_file}")
    return flag

if __name__ == "__main__":
    solve()
