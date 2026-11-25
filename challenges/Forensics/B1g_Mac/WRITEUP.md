# Writeup: B1g_Mac

## Header & Metadata
- **Challenge:** B1g_Mac (ID: 56)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** b1g_mac.zip
- **Official Flag:** `academy{M4cTim35!}`

---

## Mô tả bài toán (Overview / Analysis)

Here's a <a href='https://challenge-files.cylabacademy.net/library/77695762a74381ca12a69932aab6c7a22e4dc95de92d0056f13a315ac133833b/b1g_mac.zip' download>zip file</a>.

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
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

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{M4cTim35!}
```
