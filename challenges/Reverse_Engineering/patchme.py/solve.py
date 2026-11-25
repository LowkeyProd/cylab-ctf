#!/usr/bin/env python3
"""
Solution script for patchme.py
Category: Reverse Engineering
"""

import sys
import os
import re
from pathlib import Path

def str_xor(secret: str, key: str) -> str:
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])

def read_connection_cfg(cfg_path: Path):
    config = {}
    if cfg_path.exists():
        for line in cfg_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, v = line.split('=', 1)
                config[k.strip()] = v.strip()
    return config

def main():
    current_dir = Path(__file__).resolve().parent
    cfg_file = current_dir / "connection.cfg"
    config = read_connection_cfg(cfg_file)
    print(f"[*] Loaded configuration: {config}", flush=True)

    enc_file = current_dir / "flag.txt.enc"
    if not enc_file.exists():
        print(f"[-] {enc_file} not found locally.", flush=True)
        return

    print("[*] Reading encrypted flag...", flush=True)
    flag_enc = enc_file.read_bytes().decode("latin1", errors="replace")

    # In patchme.flag.py:
    # user_pw == "ak98" + "-=90" + "adfjhgj321" + "sleuth9000"
    # decryption = str_xor(flag_enc.decode(), "utilitarian")
    key = "utilitarian"
    print(f"[*] Decrypting with key: {key}", flush=True)
    decrypted = str_xor(flag_enc, key)
    print(f"[*] Decrypted output: {decrypted}", flush=True)

    match = re.search(r'(?:academy|picoCTF)\{[^}]+\}', decrypted)
    if not match:
        print("[-] Flag pattern not found in decrypted string.", flush=True)
        sys.exit(1)

    flag = match.group(0)

    # Reject decoys
    for decoy_word in ['decoy', 'fake', 'honeypot', 'dummy', 'not_the_flag']:
        if decoy_word in flag.lower():
            print(f"[-] Decoy flag detected: {flag}", flush=True)
            sys.exit(1)

    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = current_dir / "flag.txt"
    flag_path.write_text(flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Saved flag to {flag_path}", flush=True)

if __name__ == "__main__":
    main()
