#!/usr/bin/env python3
"""
Solve script for Classic Crackme 0x100 (#409)
"""
import socket
from pathlib import Path

TARGET_STRING = "dhomvajazmxwwmiiuhpqctvzzsxxixjkmuproxkhdruonhytwl"

def popcount(n: int) -> int:
    return bin(n % 255).count("1")

def recover_password(target: str) -> str:
    # In crackme100:
    # 3 outer iterations.
    # Each iteration: c = (c - 'a' + popcount(j)) % 26 + 'a'
    # Total shift across 3 iterations = 3 * popcount(j) mod 26.
    chars = []
    for j, c in enumerate(target):
        shift = 3 * popcount(j)
        orig_val = (ord(c) - ord("a") - shift) % 26
        chars.append(chr(ord("a") + orig_val))
    return "".join(chars)

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 48209
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("HOST=") and line.split("=", 1)[1].strip():
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1].strip():
                try:
                    p = int(line.split("=", 1)[1].strip())
                    if p > 0:
                        port = p
                except Exception:
                    pass
    return host, port

def solve():
    password = recover_password(TARGET_STRING)
    print(f"[+] Recovered Password: {password}")

    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((host, port))
        prompt = s.recv(1024).decode(errors="ignore")
        print(prompt, end="")
        s.sendall(f"{password}\n".encode())
        response = s.recv(1024).decode(errors="ignore")
        print(response)
        s.close()
    except Exception as e:
        print(f"[-] Remote connection failed: {e}")

if __name__ == "__main__":
    solve()
