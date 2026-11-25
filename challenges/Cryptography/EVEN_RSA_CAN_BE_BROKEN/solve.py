#!/usr/bin/env python3
"""
Solve script for EVEN RSA CAN BE BROKEN??? (#470)
Category: Cryptography
Target: chatelaine.cylabacademy.net:45446
Vulnerability: The RSA modulus N is even, meaning one of the prime factors is p = 2!
"""
import re
from pwn import *
from Crypto.Util.number import inverse, long_to_bytes

HOST = "chatelaine.cylabacademy.net"
PORT = 48559

def solve():
    io = remote(HOST, PORT)
    data = io.recvall(timeout=10).decode()
    io.close()

    n_match = re.search(r'N:\s*(\d+)', data)
    e_match = re.search(r'e:\s*(\d+)', data)
    c_match = re.search(r'cyphertext:\s*(\d+)', data)

    if not (n_match and e_match and c_match):
        print("[-] Failed to parse N, e, cyphertext")
        return None

    N = int(n_match.group(1))
    e = int(e_match.group(1))
    c = int(c_match.group(1))

    print(f"[+] Retrieved N: {N}")
    print(f"[+] Retrieved e: {e}")
    print(f"[+] Retrieved c: {c}")

    # Check if N is even (p = 2)
    if N % 2 == 0:
        p = 2
        q = N // p
        phi = (p - 1) * (q - 1)
        d = inverse(e, phi)
        m = pow(c, d, N)
        flag = long_to_bytes(m).decode(errors="ignore")
        print(f"[+] Decrypted Flag: {flag}")
        return flag
    else:
        print("[-] N is not even, checking small factors...")
        return None

if __name__ == "__main__":
    solve()
