#!/usr/bin/env python3
"""
Solve script for transposition-trial (#312)
Category: Cryptography
"""
import re
from pathlib import Path

def solve():
    print("[*] Solving transposition-trial...")
    msg_path = Path(__file__).parent / "message.txt"
    with open(msg_path, "r", encoding="utf-8") as f:
        ciphertext = f.read()

    # Each block of 3 characters was scrambled from (0, 1, 2) to (1, 2, 0)
    # The original was "The", scrambled into "heT" (c[0]='h', c[1]='e', c[2]='T')
    # To unscramble: new_block = block[2] + block[0] + block[1]
    plaintext_chars = []
    for i in range(0, len(ciphertext), 3):
        chunk = ciphertext[i:i+3]
        if len(chunk) == 3:
            plaintext_chars.append(chunk[2] + chunk[0] + chunk[1])
        else:
            plaintext_chars.append(chunk)

    plaintext = "".join(plaintext_chars)
    print(f"[*] Decrypted text: {plaintext}")

    match = re.search(r"(academy\{[^}]+\})", plaintext)
    if not match:
        match = re.search(r"(picoCTF\{[^}]+\})", plaintext)

    if match:
        flag = match.group(1)
        print(f"[+] Flag found: {flag}")
        flag_path = Path(__file__).parent / "flag.txt"
        with open(flag_path, "w", encoding="utf-8") as f:
            f.write(flag + "\n")
        return flag
    else:
        raise ValueError("Flag pattern not found in decrypted text")

if __name__ == "__main__":
    solve()
