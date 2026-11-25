#!/usr/bin/env python3
"""
Solve script for GDB Test Drive (#273)
Category: Reverse Engineering
"""
import os
import re
import struct
import subprocess
from pathlib import Path
import requests

def get_config():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def rot47(data: bytes) -> str:
    res = []
    for b in data:
        if 33 <= b <= 126:
            res.append(chr(33 + ((b - 33 + 47) % 94)))
        else:
            res.append(chr(b))
    return "".join(res)

def solve_via_binary_reversing(binary_path: Path):
    with open(binary_path, "rb") as f:
        content = f.read()

    # Pattern for movabs rax, imm64; movabs rdx, imm64
    # 48 b8 <8 bytes> 48 ba <8 bytes> 48 89 45 d0 48 89 55 d8 48 b8 <8 bytes> 48 ba <8 bytes>
    pattern = (
        b"\x48\xb8(.{8})\x48\xba(.{8})\x48\x89\x45\xd0\x48\x89\x55\xd8"
        b"\x48\xb8(.{8})\x48\xba(.{8})"
    )
    m = re.search(pattern, content, re.DOTALL)
    if m:
        raw_bytes = m.group(1) + m.group(2) + m.group(3) + m.group(4)
        flag_candidate = rot47(raw_bytes)
        return flag_candidate
    return None

def solve_via_gdb(binary_path: Path):
    try:
        # Try running through WSL gdb if available
        wsl_cmd = (
            f"wsl -d kali-linux bash -c \"cd '{binary_path.parent.as_posix()}' && "
            f"chmod +x '{binary_path.name}' && "
            f"gdb -batch -ex 'set confirm off' -ex 'break *(main+99)' -ex 'run' -ex 'jump *(main+104)' ./{binary_path.name}\""
        )
        out = subprocess.check_output(wsl_cmd, shell=True, text=True, stderr=subprocess.STDOUT)
        flag_match = re.search(r"(?:academy|picoCTF)\{[^\s\}]+\}", out)
        if flag_match:
            return flag_match.group(0)
    except Exception as e:
        print(f"[-] GDB run failed: {e}", flush=True)
    return None

def main():
    base_dir = Path(__file__).resolve().parent
    binary_path = base_dir / "gdbme"
    flag_path = base_dir / "flag.txt"

    cfg = get_config()
    target_url = cfg.get("URL", "")

    if not binary_path.exists() and target_url:
        print(f"[*] Downloading binary from {target_url}...", flush=True)
        r = requests.get(target_url, timeout=15)
        binary_path.write_bytes(r.content)

    print("[*] Reversing binary using ROT47 static analysis...", flush=True)
    flag = solve_via_binary_reversing(binary_path)

    if not flag:
        print("[*] Static analysis did not match pattern, running dynamic GDB test drive...", flush=True)
        flag = solve_via_gdb(binary_path)

    if flag:
        # Validate flag format and filter decoys
        for decoy in ["decoy", "fake", "honeypot", "dummy"]:
            if decoy in flag.lower():
                print(f"[-] Rejecting decoy flag: {flag}", flush=True)
                return

        print(f"[+] Flag found: {flag}", flush=True)
        flag_path.write_text(flag.strip() + "\n")
    else:
        print("[-] Flag extraction failed.", flush=True)

if __name__ == "__main__":
    main()
