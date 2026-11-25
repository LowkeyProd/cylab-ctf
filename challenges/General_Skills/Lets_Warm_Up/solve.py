#!/usr/bin/env python3
"""
Solve script for Lets Warm Up (#22)
Category: General Skills
"""
from pathlib import Path

def parse_connection_cfg(cfg_path: Path):
    config = {}
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    return config

def solve():
    base_dir = Path(__file__).resolve().parent
    parse_connection_cfg(base_dir / "connection.cfg")

    # 0x70 in hex -> ASCII char
    hex_val = 0x70
    ascii_char = chr(hex_val)

    flag = f"academy{{{ascii_char}}}"
    flag_path = base_dir / "flag.txt"
    flag_path.write_text(flag.strip() + "\n", encoding="utf-8")

    print(flag, flush=True)
    return flag

if __name__ == "__main__":
    solve()
