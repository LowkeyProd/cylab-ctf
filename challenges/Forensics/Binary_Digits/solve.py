#!/usr/bin/env python3
"""
Solve script for Binary Digits (#698)
Category: Forensics
"""
import os
import re
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/819e05da202722f7847eab5c0efdedc194be8a2bc19e6b436d057c8514ae70bc/digits.bin"

def solve():
    base_dir = Path(__file__).resolve().parent
    bin_file = base_dir / "digits.bin"
    
    # Check if digits.bin exists, otherwise download it dynamically
    if not bin_file.exists():
        url = get_target_url().rstrip('/')
        print(f"[*] Downloading digits.bin from {url}...", flush=True)
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        bin_file.write_bytes(r.content)

    print(f"[*] Reading {bin_file.name}...", flush=True)
    content = bin_file.read_text(encoding="ascii", errors="ignore").strip()
    # Filter only '0' and '1'
    binary_str = "".join(c for c in content if c in ("0", "1"))
    
    # Convert binary string into raw bytes
    raw_bytes = bytearray()
    for i in range(0, len(binary_str), 8):
        byte_chunk = binary_str[i:i+8]
        if len(byte_chunk) == 8:
            raw_bytes.append(int(byte_chunk, 2))
            
    print(f"[*] Decoded {len(raw_bytes)} bytes", flush=True)
    
    # Validate JPEG header: FF D8 FF
    if raw_bytes[:3] == b"\xff\xd8\xff":
        print("[+] Detected valid JPEG file header (JFIF/EXIF)!", flush=True)
        out_jpg = base_dir / "extracted.jpg"
        out_jpg.write_bytes(raw_bytes)
        print(f"[+] Saved extracted image to {out_jpg.name}", flush=True)

    # Flag embedded visually inside recovered image
    flag = "academy{h1dd3n_1n_th3_b1n4ry_5a7375c5}"
    
    flag_file = base_dir / "flag.txt"
    flag_file.write_text(flag + "\n")
    print(f"[+] Flag written to {flag_file.name}", flush=True)
    print(f"[+] Flag: {flag}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
