#!/usr/bin/env python3
"""
Solve script for Virtual Machine 0 (#385)
Category: Reverse Engineering
"""
import os
import sys
from pathlib import Path

def parse_connection_cfg(cfg_path="connection.cfg"):
    config = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    config[key.strip()] = val.strip()
    return config

def solve():
    print("[*] Solving Virtual Machine 0...", flush=True)
    _cfg = parse_connection_cfg()
    
    # Read input rotation count
    input_path = Path("input.txt")
    if not input_path.exists():
        print("[-] input.txt not found!", flush=True)
        return ""
    
    with open(input_path, "r") as f:
        input_num = int(f.read().strip())
    
    print(f"[*] Input rotations: {input_num}", flush=True)
    
    # The mechanical gear train consists of:
    # - Red axle (input): 40-tooth gear (part 3649)
    # - Idler axle: 8-tooth gear (part 3647)
    # - Blue axle (output): 8-tooth gear (part 3647)
    # Gear ratio: (40 / 8) * (-8 / 8) * (-1 for idler inversion) = +5
    ratio = 5
    output_num = input_num * ratio
    
    # Convert output integer to big-endian bytes
    flag_bytes = output_num.to_bytes((output_num.bit_length() + 7) // 8, byteorder="big")
    flag = flag_bytes.decode("ascii", errors="ignore")
    
    print(f"[+] Discovered flag: {flag}", flush=True)
    
    # Save to flag.txt
    with open("flag.txt", "w") as f:
        f.write(flag)
    print("[+] Flag written to flag.txt", flush=True)
    
    return flag

if __name__ == "__main__":
    solve()
