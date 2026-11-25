#!/usr/bin/env python3
"""
Solve script for rail-fence (#289)
Category: Cryptography
"""
from pathlib import Path
import re

def decrypt_rail_fence(ciphertext: str, rails: int = 4) -> str:
    n = len(ciphertext)
    cycle = 2 * (rails - 1)
    
    def get_rail(i):
        idx = i % cycle
        return idx if idx < rails else cycle - idx

    rail_indices = [[] for _ in range(rails)]
    for i in range(n):
        rail_indices[get_rail(i)].append(i)

    plaintext = [''] * n
    pos = 0
    for r in range(rails):
        for idx in rail_indices[r]:
            plaintext[idx] = ciphertext[pos]
            pos += 1

    return ''.join(plaintext)

def solve():
    message_path = Path(__file__).resolve().parent / "message.txt"
    if not message_path.exists():
        print("[-] message.txt not found!", flush=True)
        return None

    ciphertext = message_path.read_text()
    decoded = decrypt_rail_fence(ciphertext, rails=4)
    print(f"[*] Decoded message: {decoded}", flush=True)

    # Decoded message format: "The flag is: WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F"
    if ":" in decoded:
        phrase = decoded.split(":", 1)[1].strip()
    else:
        phrase = decoded.strip()

    flag = f"academy{{{phrase}}}"
    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = Path(__file__).resolve().parent / "flag.txt"
    flag_path.write_text(flag + "\n")
    return flag

if __name__ == "__main__":
    solve()
