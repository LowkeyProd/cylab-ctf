#!/usr/bin/env python3
"""
Solver for Droid0 - hard (zero.apk)
Category: Mobile / Reverse Engineering
Target: picoCTF / CyLab Academy
Flag: picoCTF{a.moose.once.bit.my.sister}
"""

import zipfile
import re

def solve():
    apk_path = "zero.apk"
    print(f"[*] Analyzing {apk_path}...")
    
    with zipfile.ZipFile(apk_path, 'r') as z:
        # Extract libhellojni.so (x86_64 or arm64-v8a)
        so_name = "lib/x86_64/libhellojni.so"
        if so_name not in z.namelist():
            so_name = [n for n in z.namelist() if n.endswith("libhellojni.so")][0]
        
        print(f"[*] Reading native library: {so_name}")
        so_data = z.read(so_name)

    # In x86_64 libhellojni.so:
    # marjoram() calls unscramble(ciphertext, 0x23, strdup("notexist"), strlen("notexist"))
    # In rodata: "notexist\0againmissing\0<ciphertext (35 bytes)>"
    pattern = b"notexist\x00againmissing\x00"
    idx = so_data.find(pattern)
    
    if idx != -1:
        key = b"notexist"
        cipher_offset = idx + len(pattern)
        cipher_len = 0x23  # 35 bytes
        ciphertext = so_data[cipher_offset : cipher_offset + cipher_len]
        
        flag = bytes([c ^ key[i % len(key)] for i, c in enumerate(ciphertext)]).decode("utf-8")
        print(f"[+] Found key: {key.decode()}")
        print(f"[+] Ciphertext length: {len(ciphertext)} bytes")
        print(f"[+] Successfully unscrambled flag: {flag}")
        return flag
    else:
        print("[-] Could not find pattern in binary.")
        return None

if __name__ == "__main__":
    solve()
