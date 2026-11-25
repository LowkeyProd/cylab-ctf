#!/usr/bin/env python3
"""
Solve script for vault-door-training (#7)
Category: Reverse Engineering
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
    return "https://challenge-files.cylabacademy.net/library/080a285021cd4d6edaff96f54c7eba477b4f450b778c0c129297bf51bbd3d3c8/VaultDoorTraining.java"

def get_source_content():
    local_java = Path(__file__).resolve().parent / "VaultDoorTraining.java"
    if local_java.exists():
        print(f"[*] Reading local file: {local_java}", flush=True)
        return local_java.read_text(encoding="utf-8")
    
    url = get_target_url().rstrip('/')
    print(f"[*] Fetching source from: {url}", flush=True)
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return r.text

def solve():
    content = get_source_content()

    # Determine prefix from substring check, e.g. "academy{" or "picoCTF{"
    prefix_match = re.search(r'substring\("([^"]+)"\.length\(\)', content)
    prefix = prefix_match.group(1) if prefix_match else "academy{"

    # Find the password string compared in checkPassword
    # e.g., return password.equals("w4rm1ng_Up_w1tH_jAv4_1633b42d7f1");
    pw_match = re.search(r'checkPassword\(String\s+password\)\s*\{\s*return\s+password\.equals\("([^"]+)"\);', content)
    if not pw_match:
        # Fallback search for any equals check
        pw_match = re.search(r'password\.equals\("([^"]+)"\)', content)

    if not pw_match:
        print("[-] Could not find password in source code.", flush=True)
        return None

    password = pw_match.group(1)
    flag = f"{prefix}{password}}}"

    # Reject decoys
    for decoy in ['decoy', 'fake', 'honeypot', 'dummy']:
        if decoy in flag.lower():
            print(f"[-] Flag rejected due to decoy keyword: {flag}", flush=True)
            return None

    print(f"[+] Flag found: {flag}", flush=True)
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Flag saved to: {flag_file}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
