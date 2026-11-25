#!/usr/bin/env python3
"""
Solve script for FactCheck (#416)
Category: Reverse Engineering
"""
import sys
from pathlib import Path

def parse_connection_cfg(cfg_path="connection.cfg"):
    config = {}
    path = Path(cfg_path)
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    config[key.strip()] = val.strip()
    return config

def solve():
    print("[*] Solving FactCheck...", flush=True)
    
    # Dynamically read connection configuration if network is ever configured
    cfg = parse_connection_cfg("connection.cfg")
    host = cfg.get("HOST", "")
    port = int(cfg.get("PORT", 0) or 0)
    url = cfg.get("URL", "")
    if host and port:
        print(f"[*] Target host: {host}:{port}", flush=True)
    if url:
        print(f"[*] Target URL: {url}", flush=True)

    bin_path = Path("bin")
    if not bin_path.exists():
        raise FileNotFoundError("Target binary 'bin' not found.")

    with open(bin_path, "rb") as f:
        data = f.read()

    # Locate base string inside .rodata
    needle = b"academy{wELF_d0N3_mate_"
    offset = data.find(needle)
    if offset == -1:
        raise ValueError("Base flag prefix not found in binary.")

    # Read null-terminated base string
    end = data.find(b"\x00", offset)
    base_flag = data[offset:end].decode("latin1")

    # In `main`, the binary instantiates local std::string variables with rodata single-char strings:
    # [rbp-0x200]: '5'
    # [rbp-0xa0]:  '6'
    # [rbp-0x1c0]: '3'
    # [rbp-0x140]: 'e'
    # [rbp-0x1e0]: '8'
    # [rbp-0x180]: '0'
    # [rbp-0x160]: 'a'
    # [rbp-0x1a0]: 'e'
    # [rbp-0x80]:  '1'
    # [rbp-0x220]: 'e'
    # [rbp-0x120]: '2'
    # [rbp-0xc0]:  '9'
    # [rbp-0x60]:  '4'
    #
    # Then it conditionally appends to s0 (rbp-0x240):
    # 1. if ord('5') <= 0x41: s0 += '9'
    # 2. if ord('6') != 0x41: s0 += '4'
    # 3. if ord('3') - ord('e') == 3: s0 += '3' (51 - 101 != 3 -> skipped)
    # 4. s0 += '8'
    # 5. s0 += '0'
    # 6. if ord('a') == 0x47: s0 += 'a' (97 != 71 -> skipped)
    # 7. s0 += 'e'
    # 8. s0 += '1'
    # 9. s0 += 'e'
    # 10. s0 += '2'
    # 11. s0 += '}'

    flag = base_flag

    if ord('5') <= 0x41:
        flag += '9'

    if ord('6') != 0x41:
        flag += '4'

    if ord('3') - ord('e') == 3:
        flag += '3'

    flag += '8'
    flag += '0'

    if ord('a') == 0x47:
        flag += 'a'

    flag += 'e'
    flag += '1'
    flag += 'e'
    flag += '2'
    flag += '}'

    # Validate flag format and guard against decoys
    decoys = ["decoy", "fake", "honeypot", "dummy", "not_the_flag"]
    if any(d in flag.lower() for d in decoys):
        raise ValueError(f"Flag rejected as decoy: {flag}")

    if not (flag.startswith("academy{") or flag.startswith("picoCTF{")):
        raise ValueError(f"Flag does not follow expected format: {flag}")

    print(f"[+] Flag found: {flag}", flush=True)

    # Save to flag.txt
    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag + "\n")
    print("[+] Saved flag to flag.txt", flush=True)

    return flag

if __name__ == "__main__":
    solve()
