#!/usr/bin/env python3
"""
Solve script for Big Zip (#322)
Category: General Skills
"""
import os
import re
import sys
import zipfile
from pathlib import Path
import urllib.request

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("URL=") and line.split("=", 1)[1]:
                return line.split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/b150f6f4d21f46fc2bba57ef49c7305541fa8e9bfa4241dfe8d066b99de56200/big-zip-files.zip"

def solve():
    script_dir = Path(__file__).resolve().parent
    zip_path = script_dir / "big-zip-files.zip"
    
    if not zip_path.exists():
        url = get_target_url()
        print(f"[*] Downloading archive from {url}...", flush=True)
        urllib.request.urlretrieve(url, zip_path)

    print(f"[*] Searching for flag in {zip_path.name}...", flush=True)
    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    found_flags = []

    with zipfile.ZipFile(zip_path, 'r') as zf:
        for file_info in zf.infolist():
            if file_info.is_dir():
                continue
            with zf.open(file_info) as f:
                content = f.read().decode('utf-8', errors='ignore')
                matches = flag_pattern.findall(content)
                for flag in matches:
                    lower_flag = flag.lower()
                    if any(decoy in lower_flag for decoy in ['decoy', 'fake', 'honeypot', 'dummy']):
                        continue
                    print(f"[+] Found candidate flag in {file_info.filename}: {flag}", flush=True)
                    found_flags.append(flag)

    if found_flags:
        final_flag = found_flags[0]
        flag_file = script_dir / "flag.txt"
        flag_file.write_text(final_flag + "\n", encoding="utf-8")
        print(f"[+] Final Flag: {final_flag}", flush=True)
        return final_flag
    else:
        print("[-] Flag not found!", flush=True)
        return None

if __name__ == "__main__":
    solve()
