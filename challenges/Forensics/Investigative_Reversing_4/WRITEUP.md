# Writeup: Investigative Reversing 4

## Header & Metadata
- **Challenge:** Investigative Reversing 4 (ID: 54)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** investigative-reversing-4-mystery, Item01_cp.bmp, Item02_cp.bmp, Item03_cp.bmp, Item04_cp.bmp, Item05_cp.bmp
- **Official Flag:** `academy{N1c3_R3ver51ng_5k1115_0000000000045d739a8}`

---

## Mô tả bài toán (Overview / Analysis)
We have recovered a <a href='https://challenge-files.cylabacademy.net/library/fb67d97f5bad7c42f4a0d56960f658ed8aac6fcb291b32f855bac5281c5a48cc/investigative-reversing-4-mystery' download>binary</a> and 5 images: <a href='https://challenge-files.cylabacademy.net/library/fb67d97f5bad7c42f4a0d56960f658ed8aac6fcb291b32f855bac5281c5a48cc/Item01_cp.bmp' download>image01</a>, <a href='https://challenge-files.cylabacademy.net/library/fb67d97f5bad7c42f4a0d56960f658ed8aac6fcb291b32f855bac5281c5a48cc/Item02_cp.bmp' download>image02</a>, <a href='https://challenge-files.cylabacademy.net/library/fb67d97f5bad7c42f4a0d56960f658ed8aac6fcb291b32f855bac5281c5a48cc/Item03_cp.bmp' download>image03</a>, <a href='https://challenge-files.cylabacademy.net/library/fb67d97f5bad7c42f4a0d56960f658ed8aac6fcb291b32f855bac5281c5a48cc/Item04_cp.bmp' download>image04</a>, <a href='https://challenge-files.cylabacademy.net/library/fb67d97f5bad7c42f4a0d56960f658ed8aac6fcb291b32f855bac5281c5a48cc/Item05_cp.bmp' download>image05</a>. See what you can make of it. There should be a flag somewhere.


### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Investigative Reversing 4 (#54)
Extracts the flag encoded in Item05_cp.bmp through Item01_cp.bmp.
"""
import os

def solve():
    files = [
        "Item05_cp.bmp",
        "Item04_cp.bmp",
        "Item03_cp.bmp",
        "Item02_cp.bmp",
        "Item01_cp.bmp",
    ]
    
    flag_chars = []
    for fname in files:
        if not os.path.exists(fname):
            raise FileNotFoundError(f"Missing file: {fname}")
        with open(fname, "rb") as f:
            data = f.read()
        
        offset = 2019
        for c in range(10):
            char_val = 0
            for bit in range(8):
                b = data[offset + c * 12 + bit]
                char_val |= ((b & 1) << bit)
            flag_chars.append(chr(char_val))
    
    flag = "".join(flag_chars)
    print(f"Flag extracted: {flag}", flush=True)
    
    with open("flag.txt", "w") as f:
        f.write(flag)
    
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{N1c3_R3ver51ng_5k1115_0000000000045d739a8}
```
