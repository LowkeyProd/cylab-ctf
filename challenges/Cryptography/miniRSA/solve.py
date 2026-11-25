#!/usr/bin/env python3
"""
Solve script for miniRSA (#73)
Category: Cryptography

Vulnerability:
With a 2048-bit modulus N and small public exponent e = 3,
the plaintext message m was not padded to the modulus size,
resulting in m^3 < N. Therefore, c = m^3 mod N = m^3 over the integers,
and the plaintext can be recovered by taking the exact integer cube root of c.
"""

import sys
import gmpy2
from Crypto.Util.number import long_to_bytes
from pathlib import Path

def solve():
    print("[*] Solving miniRSA...", flush=True)

    ciphertext_path = Path(__file__).parent / "ciphertext"
    with open(ciphertext_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    N = int(lines[0].split(":")[1].strip())
    e = int(lines[1].split(":")[1].strip())
    c = int(lines[2].split(":")[1].strip())

    print(f"[*] N bit length: {N.bit_length()}", flush=True)
    print(f"[*] e: {e}", flush=True)
    print(f"[*] c bit length: {c.bit_length()}", flush=True)

    # Check for direct integer root (or small multiples k if m^e wrapped around slightly)
    flag = ""
    for k in range(1000):
        val = c + k * N
        root, exact = gmpy2.iroot(val, e)
        if exact:
            print(f"[+] Found exact {e}-th root with k={k}!", flush=True)
            m = int(root)
            recovered = long_to_bytes(m).decode("utf-8", errors="ignore")
            print(f"[+] Decrypted text: {recovered}", flush=True)
            flag = recovered.strip()
            break

    if flag:
        flag_path = Path(__file__).parent / "flag.txt"
        with open(flag_path, "w", encoding="utf-8") as f:
            f.write(flag + "\n")
        print(f"[+] Flag written to {flag_path}: {flag}", flush=True)
    else:
        print("[-] Failed to recover flag.", flush=True)

    return flag

if __name__ == "__main__":
    solve()
