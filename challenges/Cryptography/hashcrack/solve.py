#!/usr/bin/env python3
"""
Solve script for hashcrack (#475)
Target: chatelaine.cylabacademy.net:42529
"""
from pwn import *
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 42529
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
    io = remote(host, port)
    data = io.recvall(timeout=5).decode(errors="ignore")
    print(data)
    io.close()

if __name__ == "__main__":
    solve()
