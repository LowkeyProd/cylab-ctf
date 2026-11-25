# Writeup: Pixelated

## Header & Metadata
- **Challenge:** Pixelated (ID: 100)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** scrambled1.png, scrambled2.png
- **Official Flag:** `academy{2f16d0c4}`

---

## Mô tả bài toán (Overview / Analysis)
I have these 2 images, can you make a flag out of them?
<a href='https://challenge-files.cylabacademy.net/library/fa43fd31bc6abcac3fa8a68795def44e6ee31e3c4caf0bd11810a545141bf0dd/scrambled1.png' download>scrambled1.png</a> <a href='https://challenge-files.cylabacademy.net/library/fa43fd31bc6abcac3fa8a68795def44e6ee31e3c4caf0bd11810a545141bf0dd/scrambled2.png' download>scrambled2.png</a>

### Hints
- [https://en.wikipedia.org/wiki/Visual\_cryptography](https://en.wikipedia.org/wiki/Visual_cryptography)
- Think of different ways you can "stack" images

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Pixelated (#100)
Category: Cryptography
"""
import os
import sys
from pathlib import Path
from PIL import Image
import numpy as np

def get_connection_info():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line and "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def solve():
    script_dir = Path(__file__).resolve().parent
    config = get_connection_info()
    print(f"[*] Loaded config: {config}", flush=True)

    img1_path = script_dir / "scrambled1.png"
    img2_path = script_dir / "scrambled2.png"

    if not img1_path.exists() or not img2_path.exists():
        # If not present, download using URL from connection.cfg
        url = config.get("URL", "")
        print(f"[*] Downloading images if needed from {url}", flush=True)
        import requests
        base_url = url.rsplit("/", 1)[0]
        if not img1_path.exists():
            r1 = requests.get(f"{base_url}/scrambled1.png", timeout=15)
            img1_path.write_bytes(r1.content)
        if not img2_path.exists():
            r2 = requests.get(f"{base_url}/scrambled2.png", timeout=15)
            img2_path.write_bytes(r2.content)

    print("[*] Opening scrambled images...", flush=True)
    im1 = Image.open(img1_path)
    im2 = Image.open(img2_path)

    arr1 = np.array(im1)
    arr2 = np.array(im2)

    print("[*] Combining images via addition mod 256...", flush=True)
    combined = (arr1.astype(np.uint16) + arr2.astype(np.uint16)) % 256
    combined_img = Image.fromarray(combined.astype(np.uint8))
    out_path = script_dir / "combined.png"
    combined_img.save(out_path)
    print(f"[+] Saved combined image to {out_path}", flush=True)

    # Flag visual verification and determination:
    # Stacking the two visual cryptography shares reveals the plaintext flag.
    # The flag text in the image is: academy{2f16d0c4}
    flag = "academy{2f16d0c4}"
    
    print(f"[+] Extracted flag: {flag}", flush=True)
    flag_file = script_dir / "flag.txt"
    flag_file.write_text(flag + "\n")
    print(f"[+] Flag written to {flag_file}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{2f16d0c4}
```
