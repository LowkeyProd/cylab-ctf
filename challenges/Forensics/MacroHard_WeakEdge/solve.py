#!/usr/bin/env python3
"""
Solve script for MacroHard WeakEdge (#130)
Category: Forensics
"""
import base64
import re
import sys
import zipfile
from pathlib import Path

def solve():
    print("[*] Solving MacroHard WeakEdge...", flush=True)
    
    pptm_path = Path("Forensics_is_fun.pptm")
    if not pptm_path.exists():
        raise FileNotFoundError(f"{pptm_path} not found.")

    with zipfile.ZipFile(pptm_path, 'r') as z:
        # ppt/slideMasters/hidden contains the encoded flag
        raw_hidden = z.read("ppt/slideMasters/hidden").strip()
        cleaned_b64 = raw_hidden.replace(b' ', b'').replace(b'\n', b'').replace(b'\r', b'')
        padding = (4 - len(cleaned_b64) % 4) % 4
        cleaned_b64 += b'=' * padding
        decoded = base64.b64decode(cleaned_b64).decode('utf-8', errors='ignore')
        print(f"[*] Decoded hidden content: {decoded}", flush=True)
        
        match = re.search(r'(academy\{[^\}]+\}|picoCTF\{[^\}]+\})', decoded)
        if not match:
            raise ValueError(f"Flag pattern not found in: {decoded}")
        
        flag = match.group(1)
        for bad in ['decoy', 'fake', 'honeypot', 'dummy']:
            if bad in flag.lower():
                raise ValueError(f"Decoy flag detected: {flag}")

    print(f"[+] Flag found: {flag}", flush=True)
    with open("flag.txt", "w") as f:
        f.write(flag + "\n")
    print(f"[+] Flag saved to flag.txt", flush=True)
    return flag

if __name__ == "__main__":
    solve()
