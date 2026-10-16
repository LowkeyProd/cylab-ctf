# Writeup: Investigative Reversing 2

## Header & Metadata
- **Challenge:** Investigative Reversing 2 (ID: 13)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `https://challenge-files.cylabacademy.net/library/c8f61fa3443c695c183ff25fdeadc7a4efb639f428b5e46b3122f8880e56a782/investigative-reversing-2-mystery`
- **Attached Files:** investigative-reversing-2-mystery, investigative-reversing-2-encoded.bmp
- **Official Flag:** `academy{n3xt_0n30000000000000000000000000ef4b753e}`

---

## Mô tả bài toán (Overview / Analysis)

We have recovered a <a href='https://challenge-files.cylabacademy.net/library/c8f61fa3443c695c183ff25fdeadc7a4efb639f428b5e46b3122f8880e56a782/investigative-reversing-2-mystery' download>binary</a> and an <a href='https://challenge-files.cylabacademy.net/library/c8f61fa3443c695c183ff25fdeadc7a4efb639f428b5e46b3122f8880e56a782/investigative-reversing-2-encoded.bmp' download>image</a> See what you can make of it. There should be a flag somewhere.

### Hints
- Try using some forensics skills on the image
- This problem requires both forensics and reversing skills
- What is LSB encoding?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Investigative Reversing 2 (#13)
Challenge: Forensics / Reverse Engineering
Extracts the hidden flag from investigative-reversing-2-encoded.bmp using
the reverse of the LSB steganography algorithm found in investigative-reversing-2-mystery.
"""
import sys
import os

BMP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "investigative-reversing-2-encoded.bmp")
FLAG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flag.txt")

def solve():
    with open(BMP_FILE, "rb") as f:
        bmp_data = f.read()

    # The encoder:
    # 1. Copies 2000 bytes from original.bmp to encoded.bmp
    # 2. Reads 50 characters from flag.txt
    # 3. For each char i (0..49) and each bit j (0..7):
    #      encoded_byte = (bmp_byte & 0xfe) | (((flag[i] - 5) >> j) & 1)
    # 4. Copies the remainder of original.bmp to encoded.bmp

    flag_bytes = bytearray()
    start_offset = 2000
    flag_len = 50

    for i in range(flag_len):
        char_val_minus_5 = 0
        for j in range(8):
            byte_idx = start_offset + i * 8 + j
            lsb = bmp_data[byte_idx] & 1
            char_val_minus_5 |= (lsb << j)
        char_val = (char_val_minus_5 + 5) & 0xff
        flag_bytes.append(char_val)

    flag = flag_bytes.decode("ascii", errors="replace")
    
    with open(FLAG_FILE, "w") as f:
        f.write(flag + "\n")

    print(flag)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{n3xt_0n30000000000000000000000000ef4b753e}
```
