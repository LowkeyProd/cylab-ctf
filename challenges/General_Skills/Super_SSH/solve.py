#!/usr/bin/env python3
"""
Solve script for Super SSH (#424)
Category: General Skills
"""
import re
import json
import time
from pathlib import Path
import paramiko

def parse_config():
    cfg = {}
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg

def get_ssh_credentials():
    cfg = parse_config()
    host = cfg.get("SSH_HOST")
    port = int(cfg.get("SSH_PORT", 0)) if cfg.get("SSH_PORT") else None
    user = cfg.get("SSH_USER")
    password = cfg.get("SSH_PASS")

    # If missing from connection.cfg, parse info.json or description
    if not (host and port and user and password):
        info_file = Path(__file__).resolve().parent / "info.json"
        if info_file.exists():
            data = json.loads(info_file.read_text())
            desc = data.get("description", "")
            # e.g., ssh as `ctf-player` to `chatelaine.cylabacademy.net` at port `30790`
            user_match = re.search(r"`ssh`\s+as\s+`([^`]+)`", desc)
            host_match = re.search(r"to\s+`([^`]+)`", desc)
            port_match = re.search(r"at\s+port\s+`(\d+)`", desc)
            pass_match = re.search(r"password\s+`([^`]+)`", desc)
            if user_match and not user:
                user = user_match.group(1)
            if host_match and not host:
                host = host_match.group(1)
            if port_match and not port:
                port = int(port_match.group(1))
            if pass_match and not password:
                password = pass_match.group(1)

    return host, port, user, password

def solve():
    host, port, user, password = get_ssh_credentials()
    print(f"[*] Connecting via SSH to {user}@{host}:{port}...", flush=True)

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        hostname=host,
        port=port,
        username=user,
        password=password,
        timeout=15,
        look_for_keys=False,
        allow_agent=False
    )

    # Upon connection, the MOTD or shell execution contains the flag
    stdin, stdout, stderr = ssh.exec_command('echo')
    output = stdout.read().decode('utf-8', errors='ignore')
    err = stderr.read().decode('utf-8', errors='ignore')
    all_output = output + "\n" + err

    if not re.search(r'(?:academy|picoCTF)\{[^}]+\}', all_output):
        chan = ssh.invoke_shell()
        time.sleep(2)
        all_output += "\n" + chan.recv(4096).decode('utf-8', errors='ignore')

    ssh.close()
    print(f"[*] Remote output:\n{all_output.strip()}", flush=True)

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    matches = flag_pattern.findall(all_output)

    for candidate in matches:
        cand_lower = candidate.lower()
        if any(decoy in cand_lower for decoy in ['fake', 'decoy', 'honey', 'dummy', 'not_the_flag']):
            continue
        print(f"[+] Flag found: {candidate}", flush=True)
        flag_file = Path(__file__).resolve().parent / "flag.txt"
        flag_file.write_text(candidate.strip() + "\n")
        return candidate

    print("[-] No valid flag found.", flush=True)
    return None

if __name__ == "__main__":
    solve()
