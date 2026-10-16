#!/usr/bin/env python3
"""
WebNet0 Solve Script
Decrypts TLS traffic in a PCAP file using an RSA private key with tshark,
and extracts the flag from HTTP response headers.
"""

import os
import re
import shutil
import subprocess
import sys

PCAP_FILE = os.path.abspath("webnet0-capture.pcap")
KEY_FILE = os.path.abspath("picopico.key")
FLAG_FILE = "flag.txt"

def find_tshark():
    candidates = [
        shutil.which("tshark"),
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    raise FileNotFoundError("tshark binary not found. Please ensure Wireshark/tshark is installed.")

def solve():
    tshark_bin = find_tshark()
    print(f"[*] Using tshark at: {tshark_bin}")

    cmd = [
        tshark_bin,
        "-r", PCAP_FILE,
        "-o", f'uat:rsa_keys:"{KEY_FILE}",""',
        "-Y", "http",
        "-V"
    ]

    print("[*] Decrypting TLS packets and extracting HTTP layers...")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", result.stdout)
    if not match:
        print("[-] Flag not found in decrypted traffic.")
        sys.exit(1)

    flag = match.group(1)
    print(f"[+] Found Flag: {flag}")

    with open(FLAG_FILE, "w") as f:
        f.write(flag + "\n")
    print(f"[+] Saved flag to {FLAG_FILE}")

    return flag

if __name__ == "__main__":
    solve()
