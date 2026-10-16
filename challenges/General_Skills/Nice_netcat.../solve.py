#!/usr/bin/env python3
"""
Deterministic solver for Nice netcat... (#156)
Category: General Skills
"""

import os
import re
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 43239
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("HOST=") and line.split("=", 1)[1]:
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...")

    raw_data = ""
    with socket.create_connection((host, port), timeout=10) as s:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw_data += chunk.decode("latin-1", errors="ignore")

    print("[*] Received raw numbers stream from server.")
    tokens = raw_data.strip().split()
    chars = []
    for token in tokens:
        if token.isdigit():
            chars.append(chr(int(token)))
        else:
            chars.append(token)

    decoded_text = "".join(chars)
    print(f"[*] Decoded text:\n{decoded_text}")

    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", decoded_text)
    if not match:
        raise ValueError("Flag pattern not found in decoded text!")

    flag = match.group(1).strip()
    print(f"[+] Found flag: {flag}")

    out_file = Path(__file__).resolve().parent / "flag.txt"
    out_file.write_text(flag + "\n")
    print(f"[+] Flag written to {out_file}")
    return flag

if __name__ == "__main__":
    solve()
