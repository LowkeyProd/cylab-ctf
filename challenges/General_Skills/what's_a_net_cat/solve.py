#!/usr/bin/env python3
"""
Solve script for what's a net cat? (#34)
Category: General Skills
"""
import os
import re
import socket
from pathlib import Path

def parse_connection_cfg(cfg_path: Path):
    config = {}
    if cfg_path.exists():
        for line in cfg_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            config[key.strip()] = val.strip()
    return config

def solve():
    print("[*] Solving what's a net cat?...", flush=True)
    cfg_file = Path(__file__).parent / "connection.cfg"
    config = parse_connection_cfg(cfg_file)

    host = config.get("HOST") or "xebec.cylabacademy.net"
    port_str = config.get("PORT")
    port = int(port_str) if port_str and port_str != "0" else 46647

    print(f"[*] Connecting to {host}:{port}...", flush=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10.0)
    s.connect((host, port))

    response = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break
    s.close()

    text = response.decode("utf-8", errors="replace")
    print(f"[*] Received response:\n{text}", flush=True)

    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", text)
    if not match:
        raise ValueError(f"Could not find flag in response: {text}")

    flag = match.group(1)
    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag.strip() + "\n")
    print(f"[+] Flag found: {flag}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
