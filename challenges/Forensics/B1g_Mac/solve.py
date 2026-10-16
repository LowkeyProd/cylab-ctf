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
