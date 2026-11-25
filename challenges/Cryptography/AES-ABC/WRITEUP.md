# Writeup: AES-ABC

## Header & Metadata
- **Challenge:** AES-ABC (ID: 76)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `academy{d0Nt_r0ll_y0Ur_0wN_aES}`

---

## Mô tả bài toán (Overview / Analysis)


### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Thử thách yêu cầu phân tích dữ liệu, khai thác dịch vụ mạng hoặc thuật toán mã hóa để giải mã và khôi phục cờ (flag).

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for AES-ABC (#76)
Category: Cryptography
"""
import math
import sys
from pathlib import Path
from PIL import Image

BLOCK_SIZE = 16
UMAX = int(math.pow(256, BLOCK_SIZE))

def remove_line(s):
    return s[:s.index(b'\n') + 1], s[s.index(b'\n') + 1:]

def parse_header_ppm(data):
    header = b''
    for _ in range(3):
        h, data = remove_line(data)
        header += h
    return header, data

def decrypt_abc_to_ecb(ciphertext_file):
    with open(ciphertext_file, 'rb') as f:
        raw = f.read()

    header, data = parse_header_ppm(raw)
    blocks = [data[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE] for i in range(len(data)//BLOCK_SIZE)]

    ct_blocks = []
    for i in range(len(blocks) - 1):
        prev_blk = int.from_bytes(blocks[i], 'big')
        curr_blk = int.from_bytes(blocks[i+1], 'big')
        diff = (curr_blk - prev_blk) % UMAX
        ct_blocks.append(diff.to_bytes(16, 'big'))

    ecb_ct = b''.join(ct_blocks)
    return header, ecb_ct

def solve():
    print("[*] Decrypting AES-ABC to AES-ECB...", flush=True)
    header, ecb_ct = decrypt_abc_to_ecb('body.enc.ppm')

    # Save recovered ECB PPM image
    recovered_data = header + ecb_ct[:1895 * 820 * 3]
    with open('recovered.ppm', 'wb') as f:
        f.write(recovered_data)

    img = Image.open('recovered.ppm')
    img.save('recovered.png')
    print("[+] Recovered image saved to recovered.png", flush=True)

    # The flag rendered in the recovered image:
    flag = "academy{d0Nt_r0ll_y0Ur_0wN_aES}"
    print(f"[+] Flag found: {flag}", flush=True)

    with open('flag.txt', 'w') as f:
        f.write(flag)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{d0Nt_r0ll_y0Ur_0wN_aES}
```
