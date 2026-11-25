#!/usr/bin/env python3
"""
Solve script for plumbing (#48)
Category: General Skills
"""

import os
import re
import socket
from pathlib import Path


def parse_connection_cfg(cfg_path: Path):
    host = ""
    port = 0
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("HOST="):
                    host = line.split("=", 1)[1].strip()
                elif line.startswith("PORT="):
                    val = line.split("=", 1)[1].strip()
                    if val.isdigit():
                        port = int(val)
    return host, port


def solve():
    print("[*] Solving plumbing...", flush=True)
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = parse_connection_cfg(cfg_file)

    if not host or not port:
        # Fallback to default if connection.cfg is missing or incomplete
        host = "xebec.cylabacademy.net"
        port = 45427

    print(f"[*] Connecting to {host}:{port}...", flush=True)

    flag = ""
    sock = socket.create_connection((host, port), timeout=15)
    sock.settimeout(5.0)

    received_data = []
    buffer = b""

    try:
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buffer += chunk
            # Check periodically in lines
            if b"\n" in buffer:
                lines = buffer.split(b"\n")
                buffer = lines[-1]
                for line in lines[:-1]:
                    text = line.decode("utf-8", errors="ignore").strip()
                    if "academy{" in text or "picoCTF{" in text:
                        m = re.search(r'(?:academy|picoCTF)\{[^}]+\}', text)
                        if m:
                            cand = m.group(0)
                            cand_lower = cand.lower()
                            if not any(d in cand_lower for d in ["decoy", "fake", "honey", "not_the_flag", "dummy"]):
                                flag = cand
                                break
            if flag:
                break
    except socket.timeout:
        pass
    finally:
        sock.close()

    if not flag and buffer:
        text = buffer.decode("utf-8", errors="ignore")
        m = re.search(r'(?:academy|picoCTF)\{[^}]+\}', text)
        if m:
            cand = m.group(0)
            cand_lower = cand.lower()
            if not any(d in cand_lower for d in ["decoy", "fake", "honey", "not_the_flag", "dummy"]):
                flag = cand

    if flag:
        print(f"[+] Flag found: {flag}", flush=True)
        flag_file = Path(__file__).resolve().parent / "flag.txt"
        with open(flag_file, "w", encoding="utf-8") as f:
            f.write(flag + "\n")
        print(f"[+] Saved to {flag_file}", flush=True)
    else:
        print("[-] Flag not found!", flush=True)

    return flag


if __name__ == "__main__":
    solve()
