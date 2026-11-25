#!/usr/bin/env python3
"""
Solve script for Ready Gladiator 1 (#369)
Dynamically connects to host/port in connection.cfg and deploys a Dwarf warrior against Imp.
"""
import re
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 23967
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

DWARF_WARRIOR = """\
;redcode
;name Dwarf
;assert 1
start add #4, bomb
mov bomb, @bomb
jmp start
bomb dat #0
end
"""

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)
    
    s = socket.create_connection((host, port), timeout=10)
    s.sendall(DWARF_WARRIOR.encode())
    
    response = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        except Exception:
            break
    s.close()
    
    text = response.decode(errors="ignore")
    print(text, flush=True)
    
    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", text)
    if match:
        flag = match.group(1)
        print(f"[+] Flag found: {flag}", flush=True)
        flag_path = Path(__file__).resolve().parent / "flag.txt"
        flag_path.write_text(flag.strip() + "\n")
        print(f"[+] Saved flag to {flag_path}", flush=True)
        return flag
    else:
        print("[-] Flag not found in server response.", flush=True)
        return None

if __name__ == "__main__":
    solve()
