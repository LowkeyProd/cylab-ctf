#!/usr/bin/env python3
"""
Clean, self-contained solver for asm4 (#5).
Simulates x86 assembly function asm4("academy_7749b") from test.S.
"""

import os
import re
import sys
from pathlib import Path

def parse_connection_cfg(cfg_path: Path):
    config = {}
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    return config

def parse_initial_val(asm_path: Path) -> int:
    init_val = 0x26d
    if asm_path.exists():
        content = asm_path.read_text(encoding="utf-8")
        m = re.search(r"mov\s+DWORD PTR \[ebp-0x10\],\s*(0x[0-9a-fA-F]+|\d+)", content)
        if m:
            init_val = int(m.group(1), 0)
    return init_val

def simulate_asm4(s: str, init_val: int = 0x26d) -> int:
    """
    Direct emulation of asm4 from test.S:
    - [ebp-0x10] = init_val (0x26d)
    - [ebp-0xc]  = strlen(s)
    - [ebp-0x8]  = loop counter j from 1 to strlen(s) - 2
    - Each iteration:
        ebx = res + (s[j] - s[j-1])
        res = ebx + (s[j+1] - s[j])
            = res + (s[j+1] - s[j-1])
    """
    res = init_val
    length = len(s)

    for j in range(1, length - 1):
        step = (ord(s[j]) - ord(s[j - 1])) + (ord(s[j + 1]) - ord(s[j]))
        res = (res + step) & 0xFFFFFFFF

    return res

def main():
    base_dir = Path(__file__).parent.resolve()
    cfg_file = base_dir / "connection.cfg"
    net_config = parse_connection_cfg(cfg_file)

    asm_file = base_dir / "test.S"
    init_val = parse_initial_val(asm_file)

    target_input = "academy_7749b"
    result = simulate_asm4(target_input, init_val)
    flag = hex(result)

    print(f"[*] Simulating asm4(\"{target_input}\")...", flush=True)
    print(f"[+] Flag Token: {flag}", flush=True)
    print(f"[+] FLAG: {flag}", flush=True)
    print(flag, flush=True)

    flag_path = base_dir / "flag.txt"
    flag_path.write_text(flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Saved flag to {flag_path}", flush=True)

if __name__ == "__main__":
    main()
