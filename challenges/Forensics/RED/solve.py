#!/usr/bin/env python3
"""
Solve script for RED (#460)
Category: Forensics
"""
import base64
import os
import re
import urllib.request
from pathlib import Path
from PIL import Image
import numpy as np

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/fefcf06050d98347e1585e5cb9f2940967f82e0b89c591966473c752de9f3aba/red.png"

def solve():
    base_dir = Path(__file__).resolve().parent
    img_path = base_dir / "red.png"

    if not img_path.exists():
        url = get_target_url().rstrip('/')
        print(f"[*] Downloading red.png from {url}...", flush=True)
        urllib.request.urlretrieve(url, img_path)

    print(f"[*] Reading image: {img_path}", flush=True)
    img = Image.open(img_path)
    arr = np.array(img)  # RGBA array of shape (height, width, 4)

    # Each channel's LSB holds bit sequences. Rows are identical, so row 0 suffices.
    r_lsb = (arr[0, :, 0] & 1).tolist()
    g_lsb = (arr[0, :, 1] & 1).tolist()
    b_lsb = (arr[0, :, 2] & 1).tolist()
    a_lsb = (arr[0, :, 3] & 1).tolist()

    # Interleave bits in RGBA order
    interleaved_bits = []
    for r, g, b, a in zip(r_lsb, g_lsb, b_lsb, a_lsb):
        interleaved_bits.extend([r, g, b, a])

    # Convert bit stream to bytes
    byte_vals = bytearray()
    for i in range(0, len(interleaved_bits), 8):
        byte_chunk = interleaved_bits[i:i+8]
        if len(byte_chunk) < 8:
            break
        byte_val = int("".join(map(str, byte_chunk)), 2)
        byte_vals.append(byte_val)

    payload = bytes(byte_vals)
    print(f"[*] Extracted payload: {payload}", flush=True)

    # Check for direct flag or base64 encoded flag
    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    m = flag_pattern.findall(payload.decode('latin1', errors='ignore'))

    flag = None
    if m:
        flag = m[0]
    else:
        # Try base64 decoding
        try:
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            m2 = flag_pattern.findall(decoded)
            if m2:
                flag = m2[0]
        except Exception:
            pass

    if flag:
        # Check against decoy flags
        for decoy in ['decoy', 'fake', 'honeypot', 'dummy', 'not_the_flag']:
            if decoy in flag.lower():
                print(f"[-] Decoy flag rejected: {flag}", flush=True)
                return None

        print(f"[+] Flag found: {flag}", flush=True)
        (base_dir / "flag.txt").write_text(flag.strip() + "\n")
        return flag
    else:
        print("[-] Flag not found in extracted payload.", flush=True)
        return None

if __name__ == "__main__":
    solve()
