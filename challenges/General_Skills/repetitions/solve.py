#!/usr/bin/env python3
"""
Solve script for repetitions (#371)
Category: General Skills
"""
import base64
import re
import sys
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("URL=") and len(line) > 4:
                return line.split("=", 1)[1]
    return None

def find_flag(text: str):
    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    matches = flag_pattern.findall(text)
    for m in matches:
        lower_m = m.lower()
        if any(decoy in lower_m for decoy in ['decoy', 'fake', 'honeypot', 'dummy']):
            continue
        return m
    return None

def solve():
    content = None
    url = get_target_url()
    if url:
        print(f"[*] Fetching from URL: {url}", flush=True)
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                content = r.content
        except Exception as e:
            print(f"[-] HTTP request failed: {e}, falling back to local file", flush=True)

    if not content:
        local_file = Path(__file__).resolve().parent / "enc_flag"
        if local_file.exists():
            print(f"[*] Reading local enc_flag", flush=True)
            content = local_file.read_bytes()
        else:
            print("[-] No content source found!", flush=True)
            return None

    # Repeatedly decode base64
    cur = content.strip()
    for round_idx in range(50):
        try:
            text = cur.decode('utf-8', errors='ignore')
            flag = find_flag(text)
            if flag:
                print(f"[+] Flag found at round {round_idx}: {flag}", flush=True)
                (Path(__file__).resolve().parent / "flag.txt").write_text(flag + "\n")
                return flag
        except Exception:
            pass

        try:
            cur = base64.b64decode(cur)
        except Exception as e:
            print(f"[-] Base64 decoding stopped at round {round_idx}: {e}", flush=True)
            break

    print("[-] Flag not found", flush=True)
    return None

if __name__ == "__main__":
    solve()
