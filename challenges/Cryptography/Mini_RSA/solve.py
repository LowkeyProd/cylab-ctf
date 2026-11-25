#!/usr/bin/env python3
"""
Solve script for Mini RSA (#188)
Category: Cryptography
"""
import re
import sys
from pathlib import Path
import requests
import gmpy2
from Crypto.Util.number import long_to_bytes

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("URL=") and len(line.split("=", 1)) > 1:
                return line.split("=", 1)[1].strip()
    return "https://challenge-files.cylabacademy.net/library/c38aad598cec5f49f44a9d3d52f971d09b1c834876274d278c5bfef04935fceb/values"

def get_challenge_data():
    local_values = Path(__file__).resolve().parent / "values"
    if local_values.exists() and local_values.stat().st_size > 0:
        return local_values.read_text(encoding="utf-8")
    
    url = get_target_url().rstrip('/')
    print(f"[*] Downloading values from: {url}", flush=True)
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    local_values.write_text(r.text, encoding="utf-8")
    return r.text

def integer_nth_root(n, r):
    if hasattr(gmpy2, "iroot"):
        root, exact = gmpy2.iroot(n, r)
        return int(root), bool(exact)
    # Fallback binary search
    if n < 0:
        raise ValueError("Negative number")
    if n == 0:
        return 0, True
    d = (n.bit_length() + r - 1) // r
    high = 1 << d
    low = 1 << (d - 1)
    while low <= high:
        mid = (low + high) // 2
        p = mid ** r
        if p == n:
            return mid, True
        elif p < n:
            low = mid + 1
        else:
            high = mid - 1
    return high, (high ** r == n)

def solve():
    data = get_challenge_data()
    n_match = re.search(r'N:\s*(\d+)', data)
    e_match = re.search(r'e:\s*(\d+)', data)
    c_match = re.search(r'ciphertext\s*(?:\(c\))?:\s*(\d+)', data)

    if not (n_match and e_match and c_match):
        print("[-] Failed to parse N, e, or c from data", flush=True)
        return None

    N = int(n_match.group(1))
    e = int(e_match.group(1))
    c = int(c_match.group(1))
    print(f"[*] Parsed parameters: e={e}, N bit length={N.bit_length()}", flush=True)

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    decoy_words = ['decoy', 'fake', 'honeypot', 'dummy']

    print("[*] Searching for integer root...", flush=True)
    for k in range(100000):
        val = c + k * N
        root, exact = integer_nth_root(val, e)
        if exact:
            print(f"[+] Found exact {e}-th root at k = {k}!", flush=True)
            try:
                plaintext = long_to_bytes(root).decode('utf-8', errors='ignore')
                print(f"[*] Decrypted text: {plaintext.strip()}", flush=True)
                flags = flag_pattern.findall(plaintext)
                for f in flags:
                    if not any(d in f.lower() for d in decoy_words):
                        print(f"[+] Valid flag found: {f}", flush=True)
                        flag_file = Path(__file__).resolve().parent / "flag.txt"
                        flag_file.write_text(f.strip() + "\n", encoding="utf-8")
                        return f
            except Exception as ex:
                print(f"[-] Decode error: {ex}", flush=True)
            break

    print("[-] Flag not found", flush=True)
    return None

if __name__ == "__main__":
    solve()
