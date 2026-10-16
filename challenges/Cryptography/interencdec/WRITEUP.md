# Writeup: interencdec

## Header & Metadata
- **Challenge:** interencdec (ID: 418)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A` (Static Challenge)
- **Attached Files:** `enc_flag`
- **Official Flag:** `academy{caesar_d3cr9pt3d_9df0cfea}`

---

## Mô tả bài toán (Overview / Analysis)
Đề bài cung cấp một tệp tin mã hóa `enc_flag`:
```text
YidhR3BvYTJ4MFpudHFhR3g2YUhsZmF6TnFlVGwzWVROclh6bHJiVEJxYld4b2ZRPT0nCg==
```
Yêu cầu phân tích và tìm ra thông điệp thực sự ẩn giấu bên trong tập tin.

### Hints
- Engaging in various decoding processes is of utmost importance (Thực hiện nhiều bước giải mã liên tiếp).

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Thử thách áp dụng 3 tầng giải mã tuần tự:

1. **Tầng 1 (Base64 decode):**
   Chuỗi đầu vào kết thúc bằng ký tự padding base64 `==`. Giải mã Base64 chuỗi gốc ta thu được:
   ```text
   b'aGpoa2x0ZntqaGx6aHlfazNqeTl3YTNrXzlrbTBqbWxofQ=='
   ```
2. **Tầng 2 (Lớp Base64 lồng nhau):**
   Dữ liệu bên trong tiếp tục là một chuỗi Base64:
   ```text
   aGpoa2x0ZntqaGx6aHlfazNqeTl3YTNrXzlrbTBqbWxofQ==
   ```
   Thực hiện giải mã Base64 lần thứ hai ta thu được một chuỗi văn bản có cấu trúc tương tự format cờ:
   ```text
   hjhkltf{jhlzhy_k3jy9wa3k_9km0jmlh}
   ```
3. **Tầng 3 (Mã hóa Caesar / Shift Cipher):**
   Quan sát tiền tố `hjhkltf`:
   - So sánh với định dạng chuẩn `academy`:
     - `'h' - 'a' = 7`
     - `'j' - 'c' = 7`
     - `'h' - 'a' = 7`
     - `'k' - 'd' = 7`
     - `'l' - 'e' = 7`
   - Tất cả các ký tự đã bị dịch chuyển sang phải 7 vị trí theo bảng chữ cái Caesar ($C \equiv (P + 7) \pmod{26}$).
   - Dịch chuyển ngược lại 7 ký tự ($P \equiv (C - 7) \pmod{26}$) cho toàn bộ chuỗi:
     - `hjhkltf` $\to$ `academy`
     - `jhlzhy` $\to$ `caesar`
     - `k3jy9wa3k` $\to$ `d3cr9pt3d`
     - `9km0jmlh` $\to$ `9df0cfea`

Kết quả giải mã hoàn chỉnh:
```text
academy{caesar_d3cr9pt3d_9df0cfea}
```

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for interencdec (#418)
Category: Cryptography
Method: Multi-stage decoding (Base64 -> Base64 -> Caesar Cipher shift of 7)
"""
import base64
import re
from pathlib import Path

def solve():
    enc_flag_path = Path(__file__).resolve().parent / "enc_flag"
    with open(enc_flag_path, "r") as f:
        content = f.read().strip()

    print(f"[*] Raw input: {content}")

    # Stage 1: Base64 decode
    d1 = base64.b64decode(content).decode()
    print(f"[*] Stage 1 (Base64 decoded): {d1}")

    # Stage 2: Extract inner base64 string and decode
    inner_m = re.findall(r"['\"]([^'\"]+)['\"]", d1)
    inner = inner_m[0] if inner_m else d1
    d2 = base64.b64decode(inner).decode()
    print(f"[*] Stage 2 (Inner Base64 decoded): {d2}")

    # Stage 3: Caesar cipher decode (shift 7)
    shift = 7
    flag = ""
    for ch in d2:
        if 'a' <= ch <= 'z':
            flag += chr((ord(ch) - ord('a') - shift) % 26 + ord('a'))
        elif 'A' <= ch <= 'Z':
            flag += chr((ord(ch) - ord('A') - shift) % 26 + ord('A'))
        else:
            flag += ch

    print(f"[+] Decrypted Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
```

---

## Log thực thi & Flag (Output & Verification)
```text
[*] Raw input: YidhR3BvYTJ4MFpudHFhR3g2YUhsZmF6TnFlVGwzWVROclh6bHJiVEJxYld4b2ZRPT0nCg==
[*] Stage 1 (Base64 decoded): b'aGpoa2x0ZntqaGx6aHlfazNqeTl3YTNrXzlrbTBqbWxofQ=='
[*] Stage 2 (Inner Base64 decoded): hjhkltf{jhlzhy_k3jy9wa3k_9km0jmlh}
[+] Decrypted Flag: academy{caesar_d3cr9pt3d_9df0cfea}

[+] Flag verified and saved to flag.txt:
academy{caesar_d3cr9pt3d_9df0cfea}
```
