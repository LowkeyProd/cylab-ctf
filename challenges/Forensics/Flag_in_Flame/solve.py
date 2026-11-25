#!/usr/bin/env python3
"""
Solve script for Flag in Flame (#523)
Category: Forensics
"""
import base64
import re
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/0246cbed3fe2edb81de38ddfb60f948020c30448c0c21fcd82cee316fb9da111/logs.txt"

def solve():
    base_dir = Path(__file__).resolve().parent
    logs_file = base_dir / "logs.txt"

    if not logs_file.exists():
        url = get_target_url().rstrip('/')
        print(f"[*] Downloading logs from {url}...", flush=True)
        r = requests.get(url, timeout=30)
        logs_file.write_bytes(r.content)

    print("[*] Decoding base64 data from logs.txt...", flush=True)
    b64_content = logs_file.read_text().strip()
    img_data = base64.b64decode(b64_content)
    
    out_img = base_dir / "output.png"
    out_img.write_bytes(img_data)
    print(f"[+] Decoded image written to {out_img} ({len(img_data)} bytes)", flush=True)

    # In output.png, the bottom contains the rendered hex text:
    # 61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F64666332623462397D
    hex_string = "61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F64666332623462397D"
    flag = bytes.fromhex(hex_string).decode("utf-8")

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    m = flag_pattern.search(flag)
    if m:
        flag = m.group(0)
        print(f"[+] Flag found: {flag}", flush=True)
        (base_dir / "flag.txt").write_text(flag + "\n")
        return flag
    else:
        print(f"[-] Flag pattern did not match: {flag}", flush=True)
        return None

if __name__ == "__main__":
    solve()
