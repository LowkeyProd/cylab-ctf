#!/usr/bin/env python3
"""
Solve script for Bases (#67)
Category: General Skills
"""
import base64
from pathlib import Path

def parse_connection_cfg(cfg_path: Path):
    config = {}
    if cfg_path.exists():
        for line in cfg_path.read_text().splitlines():
            if "=" in line:
                key, val = line.split("=", 1)
                config[key.strip()] = val.strip()
    return config

def solve():
    print("[*] Solving Bases...")
    cfg_path = Path(__file__).parent / "connection.cfg"
    _ = parse_connection_cfg(cfg_path)

    encoded = "bDNhcm5fdGgzX3IwcDM1"
    decoded = base64.b64decode(encoded).decode("utf-8")
    print(f"[*] Decoded string: {decoded}")

    flag = f"academy{{{decoded}}}"
    print(f"[*] Flag: {flag}")

    flag_file = Path(__file__).parent / "flag.txt"
    flag_file.write_text(flag + "\n")
    print(f"[*] Flag saved to {flag_file}")

    return flag

if __name__ == "__main__":
    solve()
