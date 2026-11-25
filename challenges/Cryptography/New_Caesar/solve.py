#!/usr/bin/env python3
"""
Solver for 'New Caesar' challenge.
"""
import string
import re
import json
from pathlib import Path

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def get_connection_config():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    if cfg_file.exists():
        for line in cfg_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def get_ciphertext():
    # Attempt to read from info.json if present
    info_path = Path(__file__).resolve().parent / "info.json"
    if info_path.exists():
        try:
            data = json.loads(info_path.read_text(encoding="utf-8"))
            desc = data.get("description", "")
            # Find 30-char ciphertext string composed of letters in alphabet
            m = re.search(r"\b([a-p]{30})\b", desc)
            if m:
                return m.group(1)
        except Exception:
            pass
    # Default ciphertext from challenge description
    return "cbdabldadbplblcnpfpnpapapecpcn"

def decrypt(enc, key):
    # Unshift
    b16 = ""
    for c in enc:
        val = (ord(c) - LOWERCASE_OFFSET - (ord(key) - LOWERCASE_OFFSET)) % len(ALPHABET)
        b16 += ALPHABET[val]
    # Decode base16
    plain = ""
    for i in range(0, len(b16), 2):
        c1 = b16[i]
        c2 = b16[i + 1]
        hi = ALPHABET.index(c1)
        lo = ALPHABET.index(c2)
        code = (hi << 4) | lo
        plain += chr(code)
    return plain

def solve():
    config = get_connection_config()
    print(f"[*] Loaded config: {config}", flush=True)

    ciphertext = get_ciphertext()
    print(f"[*] Ciphertext: {ciphertext}", flush=True)

    candidates = []
    for k in ALPHABET:
        dec = decrypt(ciphertext, k)
        if all(32 <= ord(c) < 127 for c in dec):
            score = sum(1 for c in dec if c in string.ascii_letters or c.isdigit() or c in "_?")
            candidates.append((score, k, dec))
            print(f"[*] Key '{k}' produced printable string: {dec} (score: {score})", flush=True)

    if not candidates:
        raise ValueError("[-] Failed to find printable decryption")

    # Pick candidate with highest alphanumeric / valid identifier score
    candidates.sort(key=lambda x: x[0], reverse=True)
    best_score, best_k, best_dec = candidates[0]
    candidate_flag = f"academy{{{best_dec}}}"

    print(f"[+] Found flag: {candidate_flag}", flush=True)

    # Save to flag.txt
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(candidate_flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Flag written to {flag_file}", flush=True)

    return candidate_flag

if __name__ == "__main__":
    solve()
