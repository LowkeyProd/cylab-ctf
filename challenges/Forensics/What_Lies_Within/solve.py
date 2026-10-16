#!/usr/bin/env python3
"""
Solve script for What Lies Within (#74)
Category: Forensics
Target: buildings.png
"""
import re
from PIL import Image

def solve():
    image_path = "buildings.png"
    im = Image.open(image_path)
    pixels = im.load()
    width, height = im.size

    # Extract 1-bit LSB from R, G, B channels in row-major order (b1,rgb,lsb,xy)
    bits = []
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y][:3]
            bits.append(r & 1)
            bits.append(g & 1)
            bits.append(b & 1)

    # Pack bits into bytes (MSB first)
    byte_chunks = bytearray()
    for i in range(0, len(bits), 8):
        byte_chunk = bits[i:i+8]
        if len(byte_chunk) < 8:
            break
        val = 0
        for b in byte_chunk:
            val = (val << 1) | b
        byte_chunks.append(val)
        if val == 0:  # null-terminator reached
            break

    extracted = bytes(byte_chunks).decode("utf-8", errors="ignore")
    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", extracted)
    if match:
        flag = match.group(1)
        print(f"[+] Flag found: {flag}")
        with open("flag.txt", "w") as f:
            f.write(flag + "\n")
        return flag
    else:
        print("[-] Flag not found in extracted text.")
        return None

if __name__ == "__main__":
    solve()
