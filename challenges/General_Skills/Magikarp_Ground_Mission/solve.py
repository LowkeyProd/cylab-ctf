#!/usr/bin/env python3
"""
Solve script for Magikarp Ground Mission (#189)
Category: General Skills
Domain Methodology: Computer Science & Algorithms (Easy)
"""
import sys
from pathlib import Path
import paramiko

def parse_config(cfg_path: Path):
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
                config[key.strip()] = val.strip()
    return config

def solve():
    script_dir = Path(__file__).resolve().parent
    cfg_path = script_dir / "connection.cfg"
    config = parse_config(cfg_path)

    host = config.get("HOST", "chatelaine.cylabacademy.net")
    port = int(config.get("PORT", 37440))
    username = config.get("USER", "ctf-player")
    password = config.get("PASS", "f6904eaa")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=username, password=password, timeout=15)

    # Read part 1
    _, stdout, _ = client.exec_command("cat /home/ctf-player/drop-in/1of3.flag.txt")
    part1 = stdout.read().decode("utf-8").strip()

    # Read part 2
    _, stdout, _ = client.exec_command("cat /2of3.flag.txt")
    part2 = stdout.read().decode("utf-8").strip()

    # Read part 3
    _, stdout, _ = client.exec_command("cat /home/ctf-player/3of3.flag.txt")
    part3 = stdout.read().decode("utf-8").strip()

    client.close()

    flag = f"{part1}{part2}{part3}".strip()

    # Save to flag.txt
    flag_file = script_dir / "flag.txt"
    flag_file.write_text(flag + "\n", encoding="utf-8")

    # Print exact flag cleanly to standard output
    print(flag)
    return flag

if __name__ == "__main__":
    solve()
