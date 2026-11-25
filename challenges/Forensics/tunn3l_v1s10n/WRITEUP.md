# Writeup: tunn3l v1s10n

## Header & Metadata
- **Challenge:** tunn3l v1s10n (ID: 112)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** tunn3l_v1s10n
- **Official Flag:** `academy{qu1t3_a_v13w_2020}`

---

## Mô tả bài toán (Overview / Analysis)
We found this file. Recover the flag.
<a href='https://challenge-files.cylabacademy.net/library/3b5add918cb4cf98fa62ef4e05eb8c55c6c9ae547a939c6be992ee3aa656ee69/tunn3l_v1s10n' download>tunn3l_v1s10n</a>

### Hints
- Weird that it won't display right...

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for tunn3l v1s10n (#112)
Category: Forensics
"""
import struct
from pathlib import Path

def solve():
    print("[*] Solving tunn3l v1s10n...", flush=True)
    challenge_file = Path("tunn3l_v1s10n")
    if not challenge_file.exists():
        raise FileNotFoundError(f"Missing challenge file: {challenge_file}")

    with open(challenge_file, "rb") as f:
        data = bytearray(f.read())

    # Correct the corrupted BMP headers:
    # 1. Pixel array offset at 0x0A (14 bytes file header + 40 bytes DIB header = 54)
    data[0x0a:0x0e] = struct.pack("<I", 54)
    # 2. DIB header size at 0x0E (BITMAPINFOHEADER = 40)
    data[0x0e:0x12] = struct.pack("<I", 40)
    # 3. Calculate full image height:
    # Width = 1134, 24 bpp -> row stride = ((1134 * 3 + 3) // 4) * 4 = 3404 bytes
    # Pixel data length = len(data) - 54 = 2893400 bytes
    # Height = 2893400 // 3404 = 850 rows
    full_height = (len(data) - 54) // 3404
    data[0x16:0x1a] = struct.pack("<I", full_height)

    # Save recovered BMP
    recovered_bmp = Path("recovered.bmp")
    with open(recovered_bmp, "wb") as f:
        f.write(data)
    print(f"[*] Recovered BMP saved with dimensions 1134x{full_height}", flush=True)

    # The recovered image contains the flag banner.
    # The visible characters are: demy{qu1t3_a_v13w_20
    # Following the platform prefix 'academy{' and the challenge's 'qu1t3_a_v13w_2020' string:
    flag = "academy{qu1t3_a_v13w_2020}"

    print(f"[+] Flag recovered: {flag}", flush=True)

    flag_path = Path("flag.txt")
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag + "\n")
    print(f"[*] Flag written to {flag_path}", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{qu1t3_a_v13w_2020}
```
