#!/usr/bin/env python3
"""
Solve script for WinAntiDbg0x200 (#430)
Category: Reverse Engineering
"""
import os
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

def popcount(n):
    return bin(n % 255).count('1')

def solve():
    print("[*] Solving WinAntiDbg0x200...", flush=True)
    cfg = parse_connection_cfg()
    print(f"[*] Configuration: {cfg}", flush=True)

    config_bin_path = Path("config.bin")
    if not config_bin_path.exists():
        raise FileNotFoundError("config.bin not found")

    with open(config_bin_path, "rb") as f:
        data = f.read()

    length = int.from_bytes(data[:4], "little")
    buf = data[4:]
    buf1 = list(buf[:length])
    buf2 = list(buf[length + 1 : length + 1 + length])

    # The binary calls 0x401090 with total count = 3 + 5 + 4 + 4 + 1 = 17 iterations
    # Each iteration transforms buf1 with popcount(i):
    # buf1[i] = ord('a') + ((buf1[i] - ord('a') + popcount(i)) % 26)
    total_iters = 17
    b1 = list(buf1)
    for _ in range(total_iters):
        for i in range(length):
            w = popcount(i)
            b1[i] = ord('a') + ((b1[i] - ord('a') + w) % 26)

    # 0x401180 computes buf2[i] ^= b1[i]
    flag_bytes = bytes([x ^ y for x, y in zip(b1, buf2)])
    flag = flag_bytes.decode("utf-8")

    print(f"[*] Extracted Flag: {flag}", flush=True)

    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag)

    print(f"[+] Flag written to flag.txt: {flag}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
