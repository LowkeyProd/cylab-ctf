#!/usr/bin/env python3
import base64
import re
import sys
from pathlib import Path

def solve():
    java_file = Path(__file__).resolve().parent / "SafeOpener.java"
    if not java_file.exists():
        print(f"[-] SafeOpener.java not found", flush=True)
        return None

    content = java_file.read_text(encoding="utf-8")
    
    # Extract base64 encodedkey string
    match = re.search(r'encodedkey\s*=\s*["\']([A-Za-z0-9+/=]+)["\']', content)
    if not match:
        print("[-] Could not find encodedkey in SafeOpener.java", flush=True)
        return None

    encoded_key = match.group(1)
    print(f"[*] Found encoded key: {encoded_key}", flush=True)

    # Base64 decode
    decoded_bytes = base64.b64decode(encoded_key)
    password = decoded_bytes.decode("utf-8")
    print(f"[*] Decoded password: {password}", flush=True)

    # Validate against decoys
    for bad in ["decoy", "fake", "honeypot", "dummy"]:
        if bad in password.lower():
            print(f"[-] Decoy detected: {password}", flush=True)
            return None

    flag = f"academy{{{password}}}"
    print(f"[+] Flag recovered: {flag}", flush=True)

    # Store into flag.txt
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag + "\n", encoding="utf-8")
    print(f"[+] Flag written to {flag_file.name}", flush=True)

    return flag

if __name__ == "__main__":
    solve()
