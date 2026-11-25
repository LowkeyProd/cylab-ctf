#!/usr/bin/env python3
"""
Solve script for fixme2.py (#241)
Category: General Skills
"""
import re
from pathlib import Path


def str_xor(secret, key):
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join(
        [
            chr(ord(secret_c) ^ ord(new_key_c))
            for (secret_c, new_key_c) in zip(secret, new_key)
        ]
    )


def solve():
    print("[*] Solving fixme2.py...", flush=True)

    flag_enc = (
        chr(0x04)
        + chr(0x0D)
        + chr(0x0A)
        + chr(0x0D)
        + chr(0x01)
        + chr(0x18)
        + chr(0x1C)
        + chr(0x15)
        + chr(0x58)
        + chr(0x18)
        + chr(0x11)
        + chr(0x41)
        + chr(0x09)
        + chr(0x5F)
        + chr(0x1F)
        + chr(0x10)
        + chr(0x3B)
        + chr(0x1B)
        + chr(0x55)
        + chr(0x1A)
        + chr(0x34)
        + chr(0x5D)
        + chr(0x51)
        + chr(0x40)
        + chr(0x54)
        + chr(0x09)
        + chr(0x05)
        + chr(0x04)
        + chr(0x57)
        + chr(0x1B)
        + chr(0x11)
        + chr(0x31)
        + chr(0x58)
        + chr(0x5D)
        + chr(0x55)
        + chr(0x10)
        + chr(0x00)
        + chr(0x0C)
        + chr(0x09)
        + chr(0x0A)
        + chr(0x19)
    )

    flag = str_xor(flag_enc, "enkidu")

    # Reject decoys
    if any(d in flag.lower() for d in ["decoy", "fake", "honeypot", "dummy"]):
        raise ValueError("Decoy flag detected!")

    print(f"[+] Flag found: {flag}", flush=True)
    Path("flag.txt").write_text(flag.strip())
    print("[+] Saved flag to flag.txt", flush=True)
    return flag


if __name__ == "__main__":
    solve()
