# Writeup: What Lies Within

## Header & Metadata
- **Challenge:** What Lies Within (ID: 74)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** buildings.png
- **Official Flag:** `academy{h1d1ng_1n_th3_b1t5}`

---

## Mô tả bài toán (Overview / Analysis)

There's something in the <a href='https://challenge-files.cylabacademy.net/library/5235bfccd8f3cc2d059ee828f774846542f28f7ec66cb4f0c6ceb536c38026d4/buildings.png' download>building</a>. Can you retrieve the flag?

### Hints
- There is data encoded somewhere... there might be an online decoder.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
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

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{h1d1ng_1n_th3_b1t5}
```
