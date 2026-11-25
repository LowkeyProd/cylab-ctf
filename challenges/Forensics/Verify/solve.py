#!/usr/bin/env python3
"""
Solve script for Verify (#450)
Category: Forensics
"""
import re
import sys
from pathlib import Path
import paramiko


def parse_connection_cfg(cfg_path: Path):
    config = {}
    if not cfg_path.exists():
        return config
    with open(cfg_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                config[key.strip().upper()] = val.strip()
    return config


def solve():
    print("[*] Solving Verify (#450)...")
    curr_dir = Path(__file__).resolve().parent
    cfg_file = curr_dir / "connection.cfg"
    config = parse_connection_cfg(cfg_file)

    host = config.get("HOST", "")
    port = int(config.get("PORT", 0)) if config.get("PORT") else 22
    username = config.get("USERNAME", "ctf-player")
    password = config.get("PASSWORD", "fd7746b4")

    # Fallback to info.json if connection.cfg is missing host or port
    info_file = curr_dir / "info.json"
    if not host and info_file.exists():
        import json
        with open(info_file, "r", encoding="utf-8") as f:
            info_data = json.load(f)
        desc = info_data.get("description", "")
        m_ssh = re.search(r"ssh\s+-p\s+(\d+)\s+([^\s@]+)@([^\s`]+)", desc)
        if m_ssh:
            port = int(m_ssh.group(1))
            username = m_ssh.group(2)
            host = m_ssh.group(3)
        m_pass = re.search(r"`([a-f0-9]{8})`", desc)
        if m_pass:
            password = m_pass.group(1)

    print(f"[*] Connecting to {username}@{host}:{port}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=username, password=password, timeout=20)

    # Read checksum from drop-in/checksum.txt
    stdin, stdout, stderr = client.exec_command("cat drop-in/checksum.txt")
    target_checksum = stdout.read().decode().strip()
    if not target_checksum:
        target_checksum = "deb0a6ad170cd3033d30cae15146719dd4abf37d39136bcb10d88d9c33413374"
    print(f"[*] Target checksum: {target_checksum}")

    # Search for matching file
    cmd = f"cd drop-in && sha256sum files/* | grep {target_checksum}"
    stdin, stdout, stderr = client.exec_command(cmd)
    res = stdout.read().decode().strip()
    if not res:
        client.close()
        raise RuntimeError("No file matched target checksum!")

    matched_rel_path = res.split()[-1]
    print(f"[*] Matched file: {matched_rel_path}")

    # Run decrypt script
    decrypt_cmd = f"cd drop-in && ./decrypt.sh {matched_rel_path}"
    stdin, stdout, stderr = client.exec_command(decrypt_cmd)
    output = stdout.read().decode().strip()
    client.close()

    print(f"[*] Decrypt output: {output}")

    match = re.search(r"(academy\{[^\}]+\}|picoCTF\{[^\}]+\})", output)
    if not match:
        raise ValueError(f"Flag pattern not found in output: {output}")

    flag = match.group(1)
    flag_file = curr_dir / "flag.txt"
    flag_file.write_text(flag, encoding="utf-8")
    print(f"[+] Flag found: {flag}")
    print(f"[+] Flag written to {flag_file}")
    return flag


if __name__ == "__main__":
    solve()
