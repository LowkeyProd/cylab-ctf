#!/usr/bin/env python3
"""
Solve script for substitution2 (#309)
Category: Cryptography
"""
from pathlib import Path
import re

def solve():
    print("[*] Solving substitution2...", flush=True)
    msg_path = Path("message.txt")
    if not msg_path.exists():
        raise FileNotFoundError("message.txt not found")

    text = msg_path.read_text().strip()

    # Substitution mapping discovered via frequency and n-gram analysis
    mapping = {
        'a': 'n', 'b': 'y', 'c': 'h', 'e': 'c', 'f': 'q', 'g': 'i', 'h': 'x',
        'i': 'f', 'j': 'm', 'k': 'w', 'l': 'e', 'm': 'l', 'n': 'v', 'o': 'd',
        'p': 'o', 'r': 'a', 's': 'r', 't': 'g', 'u': 's', 'v': 'u', 'w': 'b',
        'x': 't', 'y': 'p', 'z': 'k'
    }

    decrypted_chars = []
    for c in text:
        if c in mapping:
            decrypted_chars.append(mapping[c])
        elif c.lower() in mapping:
            decrypted_chars.append(mapping[c.lower()].upper())
        else:
            decrypted_chars.append(c)

    decrypted_text = "".join(decrypted_chars)
    print(f"[*] Decrypted preview: {decrypted_text[:100]}...", flush=True)

    match = re.search(r"(academy\{[^}]+\})", decrypted_text)
    if not match:
        raise ValueError("Flag pattern not found in decrypted text")

    flag = match.group(1)
    print(f"[+] Flag found: {flag}", flush=True)

    with open("flag.txt", "w") as f:
        f.write(flag + "\n")
    print("[+] Saved flag to flag.txt", flush=True)
    return flag

if __name__ == "__main__":
    solve()
