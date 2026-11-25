#!/usr/bin/env python3
"""
Solve script for WinAntiDbg0x100 (#429)
Category: Reverse Engineering
"""
import os
import zipfile
from pathlib import Path

def parse_connection_cfg(cfg_path="connection.cfg"):
    cfg = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    return cfg

def popcount(x):
    # SWAR popcount matching the binary's assembly implementation
    val = x % 255
    step1 = (val & 0x55) + ((val >> 1) & 0x55)
    step2 = (step1 & 0x33) + ((step1 >> 2) & 0x33)
    return (step2 & 0x0F) + ((step2 >> 4) & 0x0F)

def transform(buf, times):
    buf = list(buf)
    L = len(buf)
    for _ in range(times):
        for j in range(L):
            p = popcount(j)
            buf[j] = ord('a') + ((buf[j] - ord('a') + p) % 26)
    return bytes(buf)

def solve():
    print("[*] Reading target configuration...", flush=True)
    cfg = parse_connection_cfg()
    print(f"[*] Target config: {cfg}", flush=True)

    config_bin_path = Path("config.bin")
    if not config_bin_path.exists():
        zip_path = Path("WinAntiDbg0x100.zip")
        if zip_path.exists():
            print("[*] Extracting challenge files from zip...", flush=True)
            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(pwd=b"academy")
        else:
            raise FileNotFoundError("Neither config.bin nor WinAntiDbg0x100.zip found!")

    with open(config_bin_path, "rb") as f:
        data = f.read()

    # Binary parses 4-byte little endian length L
    length = int.from_bytes(data[:4], "little")
    part2 = data[4:4 + length]
    # Followed by 1 null byte separator, then part3 of length L
    part3 = data[4 + length + 1: 4 + length + 1 + length]

    print(f"[*] Parsing config.bin: length = {length}", flush=True)

    # In WinAntiDbg0x100:
    # 1. Calls transform(part2, 7)
    # 2. Checks IsDebuggerPresent() -> when bypassed (0), jumps to transform(part2, 11)
    # Total transformations = 7 + 11 = 18
    # 3. XORs transformed part2 with part3
    transformed_part2 = transform(part2, 18)
    decrypted_bytes = bytes([a ^ b for a, b in zip(part3, transformed_part2)])
    flag = decrypted_bytes.decode("utf-8", errors="replace")

    print(f"[+] Flag found: {flag}", flush=True)

    # Save to flag.txt
    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag)
    print("[+] Saved flag to flag.txt", flush=True)

    return flag

if __name__ == "__main__":
    solve()
