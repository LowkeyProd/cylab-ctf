#!/usr/bin/env python3
"""
Solve script for unpackme.py (#314)
Category: Reverse Engineering
"""
import base64
import re
from pathlib import Path
from cryptography.fernet import Fernet
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/d78f54f4620ec8d4a6f17fa02080e00306f51d33831dd2ea2d1a1366905d3c47/unpackme.flag.py"

def solve():
    script_dir = Path(__file__).resolve().parent
    target_file = script_dir / "unpackme.flag.py"
    
    code = ""
    # Try fetching latest from target URL if specified in connection.cfg
    try:
        url = get_target_url()
        print(f"[*] Checking connection config URL: {url}", flush=True)
        r = requests.get(url, timeout=5)
        if r.status_code == 200 and "Fernet" in r.text:
            print("[+] Successfully fetched unpackme script from URL", flush=True)
            code = r.text
    except Exception as e:
        print(f"[-] Could not fetch from URL: {e}", flush=True)

    if not code and target_file.exists():
        print("[*] Reading local unpackme.flag.py", flush=True)
        code = target_file.read_text()

    if not code:
        print("[-] Target file or code could not be loaded", flush=True)
        return None

    # Extract payload and key_str using regex
    payload_match = re.search(r"payload\s*=\s*(b?['\"]([^'\"]+)['\"])", code)
    key_match = re.search(r"key_str\s*=\s*['\"]([^'\"]+)['\"]", code)

    if not payload_match or not key_match:
        print("[-] Failed to extract payload or key_str", flush=True)
        return None

    payload = payload_match.group(2).encode('utf-8')
    key_str = key_match.group(1)

    print(f"[*] Extracted payload length: {len(payload)} bytes", flush=True)
    print(f"[*] Extracted key_str: {key_str}", flush=True)

    key_base64 = base64.b64encode(key_str.encode('utf-8'))
    f = Fernet(key_base64)
    plain = f.decrypt(payload).decode('utf-8')
    print("[+] Decrypted unpacked code successfully", flush=True)

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    matches = flag_pattern.findall(plain)
    for flag in matches:
        if any(decoy in flag.lower() for decoy in ['fake', 'decoy', 'honey', 'dummy', 'not_the_flag']):
            continue
        print(f"[+] Flag found: {flag}", flush=True)
        flag_file = script_dir / "flag.txt"
        flag_file.write_text(flag + "\n")
        print(f"[+] Flag written to {flag_file}", flush=True)
        return flag

    print("[-] Flag not found in decrypted payload", flush=True)
    return None

if __name__ == "__main__":
    solve()
