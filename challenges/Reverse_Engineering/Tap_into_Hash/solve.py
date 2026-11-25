#!/usr/bin/env python3
"""
Solve script for Tap into Hash (#466)
Category: Reverse Engineering
"""
import ast
import hashlib
import re
from pathlib import Path


def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len < 1 or padding_len > 16:
        return data
    if data[-padding_len:] == bytes([padding_len] * padding_len):
        return data[:-padding_len]
    return data


def solve():
    print("[*] Solving Tap into Hash...", flush=True)

    # Read connection.cfg if present
    cfg_path = Path("connection.cfg")
    config = {}
    if cfg_path.exists():
        for line in cfg_path.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()

    enc_flag_path = Path("enc_flag")
    if not enc_flag_path.exists():
        raise FileNotFoundError("enc_flag not found")

    lines = enc_flag_path.read_text().splitlines()
    key_line = lines[0]
    enc_line = lines[1]

    key_bytes = ast.literal_eval(key_line.split(": ", 1)[1])
    ciphertext = ast.literal_eval(enc_line.split(": ", 1)[1])

    key_hash = hashlib.sha256(key_bytes).digest()
    block_size = 16

    plaintext_bytes = bytearray()
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        dec_block = bytes(x ^ y for x, y in zip(block, key_hash))
        plaintext_bytes.extend(dec_block)

    unpadded = unpad(bytes(plaintext_bytes))
    plaintext_str = unpadded.decode("utf-8", errors="ignore")

    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", plaintext_str)
    if not match:
        raise ValueError(f"Flag not found in decrypted plaintext: {plaintext_str}")

    flag = match.group(1)

    # Reject decoys
    for decoy in ["fake", "decoy", "honey", "not_the_flag", "dummy"]:
        if decoy in flag.lower():
            raise ValueError(f"Decoy flag rejected: {flag}")

    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = Path("flag.txt")
    flag_path.write_text(flag)
    print(f"[+] Flag written to {flag_path}", flush=True)

    return flag


if __name__ == "__main__":
    solve()
