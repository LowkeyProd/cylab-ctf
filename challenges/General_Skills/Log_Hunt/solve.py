#!/usr/bin/env python3
"""
Solve script for Log Hunt (#527)
Category: General Skills
"""
import os
import re
import sys
import requests
from pathlib import Path

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("URL=") and len(line) > 4:
                return line.split("=", 1)[1].strip()
    return None

def extract_flag(log_content: str) -> str:
    flag_parts = []
    seen = set()
    for line in log_content.splitlines():
        if "FLAGPART:" in line:
            part = line.split("FLAGPART:", 1)[1].strip()
            if part not in seen:
                seen.add(part)
                flag_parts.append(part)
            if part.endswith("}"):
                break
    reconstructed = "".join(flag_parts)
    return reconstructed

def solve():
    script_dir = Path(__file__).resolve().parent
    local_log = script_dir / "server.log"
    log_content = None

    if local_log.exists():
        print(f"[*] Reading local log file: {local_log}", flush=True)
        log_content = local_log.read_text(encoding="utf-8", errors="ignore")
    else:
        url = get_target_url()
        if url:
            print(f"[*] Fetching log from URL: {url}", flush=True)
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            log_content = resp.text
        else:
            print("[-] No local log file and no URL found in connection.cfg", flush=True)
            sys.exit(1)

    flag = extract_flag(log_content)
    print(f"[*] Extracted string: {flag}", flush=True)

    flag_pattern = re.compile(r'^(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}$')
    if not flag_pattern.match(flag):
        print(f"[-] Extracted string does not match flag format: {flag}", flush=True)
        sys.exit(1)

    for decoy in ['decoy', 'fake', 'honeypot', 'dummy']:
        if decoy in flag.lower():
            print(f"[-] Decoy detected in flag: {flag}", flush=True)
            sys.exit(1)

    flag_file = script_dir / "flag.txt"
    flag_file.write_text(flag + "\n", encoding="utf-8")
    print(f"[+] Flag found and saved: {flag}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
