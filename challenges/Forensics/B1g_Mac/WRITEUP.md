# Writeup: B1g_Mac (#56)

## 1. Header & Metadata
- **Challenge Name:** B1g_Mac
- **Challenge ID:** 56
- **Category:** Forensics
- **Difficulty:** Hard
- **CTF Event:** CyLab Academy / picoCTF
- **Official Flag:** `academy{M4cTim35!}`

---

## 2. Overview / Analysis
Challenge cung cấp một file nén `b1g_mac.zip` chứa một file thực thi `main.exe` và thư mục `test/` gồm nhiều ảnh bitmap (`Item01.bmp`, `Item01 - Copy.bmp`, ..., `ItemTest - Copy.bmp`).

Khi giải nén thông thường, các file ảnh không chứa nội dung bất thường. Tuy nhiên, tên bài toán gợi ý về **MAC times** (Modified, Accessed, Created timestamps) trong hệ thống tệp NTFS của Windows.

---

## 3. Technical Deep-Dive
Trong định dạng lưu trữ file ZIP theo chuẩn PKWARE:
1. Mỗi tệp tin trong archive có thể chứa các trường mở rộng (**Extra Fields**) với Header ID định danh chuẩn:
   - Header ID `0x000a`: **NTFS Extra Field Tag**.
2. Cấu trúc trường NTFS Extra Field:
   - 2 bytes Header ID (`0x000a`)
   - 2 bytes Data Size
   - 4 bytes Reserved
   - 2 bytes Attribute Tag (`0x0001` cho NTFS attributes)
   - 2 bytes Attribute Size (`0x0018` = 24 bytes)
   - 8 bytes **MTime** (Modified Time, Windows 64-bit FILETIME)
   - 8 bytes **ATime** (Access Time)
   - 8 bytes **CTime** (Creation Time)
3. Phân tích giá trị MTime của các file `test/Item* - Copy.bmp`:
   - `Item01 - Copy.bmp`: `mtime = 0x1d4e36149336163` -> 2 byte cuối: `0x61` ('a'), `0x63` ('c')
   - `Item02 - Copy.bmp`: `mtime = 0x1d4e36158b26164` -> `0x61` ('a'), `0x64` ('d')
   - `Item03 - Copy.bmp`: `mtime = 0x1d4e36162d4656d` -> `0x65` ('e'), `0x6d` ('m')
   - `Item04 - Copy.bmp`: `mtime = 0x1d4e3616ff1797b` -> `0x79` ('y'), `0x7b` ('{')
   - `Item05 - Copy.bmp`: `mtime = 0x1d4e361797a4d34` -> `0x4d` ('M'), `0x34` ('4')
   - `Item06 - Copy.bmp`: `mtime = 0x1d4e361de356354` -> `0x63` ('c'), `0x54` ('T')
   - `Item07 - Copy.bmp`: `mtime = 0x1d4e361ef7f696d` -> `0x69` ('i'), `0x6d` ('m')
   - `Item08 - Copy.bmp`: `mtime = 0x1d4e36218073335` -> `0x33` ('3'), `0x35` ('5')
   - `ItemTest - Copy.bmp`: `mtime = 0x1d4e3690675217d` -> `0x21` ('!'), `0x7d` ('}')

Ghép các ký tự theo thứ tự tên tệp cho ra: `academy{M4cTim35!}`.

---

## 4. Solve Script (`solve.py`)
```python
#!/usr/bin/env python3
"""
Automated Solver for B1g_Mac (#56)
Extracts flag characters encoded in ZIP NTFS FILETIME attributes.
"""
import zipfile
import struct
import re
from pathlib import Path

def solve():
    zip_path = Path(__file__).resolve().parent / "b1g_mac.zip"
    zf = zipfile.ZipFile(zip_path, 'r')
    
    entries = []
    for info in zf.infolist():
        extra = info.extra
        idx = 0
        while idx + 4 <= len(extra):
            header_id, size = struct.unpack('<HH', extra[idx:idx+4])
            idx += 4
            if header_id == 0x000a:
                ntfs_data = extra[idx:idx+size]
                if len(ntfs_data) >= 16:
                    mtime = struct.unpack('<Q', ntfs_data[8:16])[0]
                    entries.append((info.filename, mtime))
            idx += size

    # Filter files containing 'Copy' and sort alphabetically
    copy_files = sorted([e for e in entries if "Copy" in e[0]], key=lambda x: x[0])
    chars = []
    for fn, mt in copy_files:
        b1 = (mt >> 8) & 0xff
        b2 = mt & 0xff
        chars.extend([chr(b1), chr(b2)])
        
    flag = "".join(chars)
    print(f"[+] Recovered Flag: {flag}")
    
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag + "\n")
    return flag

if __name__ == "__main__":
    solve()
```

---

## 5. Output & Verification
```bash
$ python3 solve.py
[+] Recovered Flag: academy{M4cTim35!}
```
- **Flag chính thức:** `academy{M4cTim35!}`
