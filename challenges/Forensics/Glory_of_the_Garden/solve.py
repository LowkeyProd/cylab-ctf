#!/usr/bin/env python3
"""
Solve script for Glory of the Garden (#44)
Category: Forensics
"""
import re
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return None

def solve():
    script_dir = Path(__file__).resolve().parent
    local_file = script_dir / "garden.jpg"
    
    data = None
    if local_file.exists():
        print(f"[*] Reading local challenge file: {local_file.name}")
        data = local_file.read_bytes()
    else:
        url = get_target_url()
        if url:
            print(f"[*] Downloading target from: {url}")
            r = requests.get(url, timeout=10)
            data = r.content
        else:
            print("[-] No local file or target URL found.")
            return None

    flag_pattern = re.compile(rb'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    m = flag_pattern.findall(data)
    if m:
        flag = m[0].decode('utf-8', errors='ignore')
        print(f"[+] Flag found: {flag}")
        (script_dir / "flag.txt").write_text(flag + "\n")
        return flag

    print("[-] Flag not found.")
    return None

if __name__ == "__main__":
    solve()
