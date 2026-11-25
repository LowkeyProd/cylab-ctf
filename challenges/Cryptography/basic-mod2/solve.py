#!/usr/bin/env python3
"""
Solve script for basic-mod2 (#254)
Category: Cryptography
"""
from pathlib import Path
import string

def solve():
    print("[*] Solving basic-mod2...", flush=True)
    message_file = Path(__file__).parent / "message.txt"
    with open(message_file, "r") as f:
        content = f.read().strip()

    numbers = [int(x) for x in content.split()]

    # 1-26 are the alphabet, 27-36 are the decimal digits, 37 is underscore
    # Using 1-based indexing
    mapping = {}
    for i, ch in enumerate(string.ascii_uppercase, start=1):
        mapping[i] = ch
    for i, ch in enumerate(string.digits, start=27):
        mapping[i] = ch
    mapping[37] = "_"

    decrypted = []
    for n in numbers:
        mod_val = n % 41
        inv = pow(mod_val, -1, 41)
        decrypted.append(mapping[inv])

    msg = "".join(decrypted)
    flag = f"academy{{{msg}}}"

    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag)
    print(f"[+] Saved flag to {flag_path}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
