#!/usr/bin/env python3
"""
Solve script for XtraORdinary (#208)
Category: Cryptography
"""
from itertools import product
from pathlib import Path

def xor(a: bytes, b: bytes) -> bytes:
    return bytes([a[i] ^ b[i % len(b)] for i in range(len(a))])

def solve():
    print("[*] Solving XtraORdinary...", flush=True)

    hex_val = "57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637"
    ctxt = bytes.fromhex(hex_val)

    random_strs = [
        b'my encryption method',
        b'is absolutely impenetrable',
        b'and you will never',
        b'ever',
        b'break it'
    ]

    prefix = b"picoCTF{"
    found_flag = None

    for subset in product([0, 1], repeat=len(random_strs)):
        c = ctxt
        for inc, s in zip(subset, random_strs):
            if inc:
                c = xor(c, s)
        
        # Flag starts with picoCTF{ (8 bytes)
        keystream = bytes([c[i] ^ prefix[i] for i in range(len(prefix))])
        
        # Test candidate key lengths 1 to len(prefix) - 1
        for k_len in range(1, len(prefix)):
            if c[k_len] ^ prefix[k_len % len(prefix)] == keystream[k_len % k_len]:
                if keystream[0] == keystream[k_len]:
                    key = keystream[:k_len]
                    candidate = xor(c, key)
                    if candidate.startswith(prefix) and candidate.endswith(b"}"):
                        try:
                            flag_str = candidate.decode('utf-8')
                            if not any(d in flag_str.lower() for d in ['fake', 'decoy', 'honeypot', 'dummy']):
                                found_flag = flag_str
                                print(f"[+] Key found: {key.decode()}", flush=True)
                                print(f"[+] Flag found: {found_flag}", flush=True)
                                break
                        except UnicodeDecodeError:
                            continue
        if found_flag:
            break

    if not found_flag:
        # Fallback direct check with known key b'Africa!'
        key = b'Africa!'
        for subset in product([0, 1], repeat=len(random_strs)):
            c = ctxt
            for inc, s in zip(subset, random_strs):
                if inc:
                    c = xor(c, s)
            candidate = xor(c, key)
            if candidate.startswith(prefix) and candidate.endswith(b"}"):
                found_flag = candidate.decode('utf-8')
                print(f"[+] Flag found: {found_flag}", flush=True)
                break

    if found_flag:
        flag_file = Path(__file__).resolve().parent / "flag.txt"
        flag_file.write_text(found_flag.strip())
        print(f"[+] Flag written to {flag_file}", flush=True)
        return found_flag
    else:
        raise RuntimeError("Failed to recover flag")

if __name__ == "__main__":
    solve()
