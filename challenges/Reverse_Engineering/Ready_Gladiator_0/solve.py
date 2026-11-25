#!/usr/bin/env python3
"""
Solve script for Ready Gladiator 0 (#368)
Target dynamically read from connection.cfg
"""
import re
import socket
import time
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 13600
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
    print(f"[*] Connecting to {host}:{port}...", flush=True)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    # Receive banner / prompt
    initial = s.recv(1024).decode(errors="ignore")
    print(f"[*] Received: {initial.strip()}", flush=True)
    
    # CoreWars warrior that terminates immediately upon execution (DAT instruction kills process)
    # causing warrior 1 to lose all 100 rounds with 0 ties.
    payload = ";redcode\n;name Loser\n;assert 1\ndat 0, 0\nend\n"
    s.sendall(payload.encode())
    
    response = b""
    while True:
        try:
            s.settimeout(3.0)
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        except Exception:
            break
    s.close()
    
    output = response.decode(errors="ignore")
    print(f"[*] Server response:\n{output}", flush=True)
    
    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", output)
    if match:
        flag = match.group(1)
        print(f"[+] Flag found: {flag}", flush=True)
        with open("flag.txt", "w") as f:
            f.write(flag + "\n")
        print("[+] Flag saved to flag.txt", flush=True)
        return flag
    else:
        print("[-] Flag not found in output", flush=True)
        return None

if __name__ == "__main__":
    solve()
