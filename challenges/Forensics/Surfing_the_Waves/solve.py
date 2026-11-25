#!/usr/bin/env python3
"""
Solve script for Surfing the Waves (#117)
Category: Forensics
"""
import wave
import struct
import string
import re
from pathlib import Path

def solve():
    print("[*] Solving Surfing the Waves...", flush=True)
    wav_path = Path(__file__).parent / "main.wav"
    
    with wave.open(str(wav_path), 'rb') as w:
        nframes = w.getnframes()
        frames = w.readframes(nframes)
        samples = struct.unpack(f"<{nframes}h", frames)
    
    # Each sample was encoded as: 1000 + int(hex_digit) * 500 + noise
    # Reverse mapping:
    # hex_digit = (sample - 1000) // 500 = sample // 500 - 2
    hex_str = ''.join(string.hexdigits[s // 500 - 2] for s in samples)
    decoded_text = bytes.fromhex(hex_str).decode('utf-8')
    
    match = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', decoded_text)
    if not match:
        raise ValueError("Flag pattern not found in decoded payload!")
    
    flag = match.group(1)
    print(f"[+] Flag found: {flag}", flush=True)
    
    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag)
    return flag

if __name__ == "__main__":
    solve()
