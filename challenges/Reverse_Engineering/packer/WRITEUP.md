# Writeup: packer

## Header & Metadata
- **Challenge:** packer (ID: 421)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** out
- **Official Flag:** `academy{U9X_UnP4ck1N6_B1n4Ri3S_ad49ff7a}`

---

## Mô tả bài toán (Overview / Analysis)
Reverse this linux executable?

<a href='https://challenge-files.cylabacademy.net/library/f1037dbfd1862e9e05024e3cc566edfd9ddfb9ea7fcef199392ee015309d414d/out' download>binary</a>


### Hints
- What can we do to reduce the size of a binary after compiling it.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for packer (#421)
Category: Reverse Engineering
"""
import os
import re
import subprocess
from pathlib import Path

def parse_connection_cfg(cfg_path="connection.cfg"):
    config = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    return config

def unpack_binary(input_file="out", output_file="unpacked"):
    if os.path.exists(output_file):
        return output_file
    
    # Try native upx first
    try:
        subprocess.run(["upx", "-d", "-o", output_file, input_file], capture_output=True, check=True)
        return output_file
    except Exception:
        pass

    # Try WSL upx
    try:
        cur_dir = os.path.abspath(os.path.dirname(__file__))
        wsl_cur_dir = cur_dir.replace("\\", "/").replace("C:", "/mnt/c")
        cmd = f"cd '{wsl_cur_dir}' && cp '{input_file}' '{output_file}' && upx -d '{output_file}'"
        subprocess.run(["wsl", "bash", "-c", cmd], capture_output=True, check=True)
        return output_file
    except Exception as e:
        print(f"[-] UPX unpacking failed: {e}", flush=True)

    return None

def extract_flag():
    cfg = parse_connection_cfg()
    print(f"[*] Connection config: {cfg}", flush=True)

    unpacked_path = unpack_binary("out", "unpacked")
    target_path = unpacked_path if (unpacked_path and os.path.exists(unpacked_path)) else "out"

    print(f"[*] Analyzing binary: {target_path}", flush=True)
    with open(target_path, "rb") as f:
        data = f.read()

    # Search for hex-encoded academy{...} flag (61636164656d79...)
    hex_pattern = rb"61636164656d797b[0-9a-fA-F]+7d"
    match = re.search(hex_pattern, data)
    if match:
        hex_str = match.group(0).decode("ascii")
        flag = bytes.fromhex(hex_str).decode("utf-8")
        print(f"[*] Found hex-encoded flag: {hex_str}", flush=True)
        return flag

    # Search for plaintext flag pattern directly
    ascii_pattern = rb"(academy\{[^\}]+\}|picoCTF\{[^\}]+\})"
    match = re.search(ascii_pattern, data)
    if match:
        flag = match.group(0).decode("utf-8")
        return flag

    return None

def solve():
    print("[*] Solving packer...", flush=True)
    flag = extract_flag()
    if not flag:
        raise ValueError("Flag not found!")

    for decoy in ["decoy", "fake", "honeypot", "dummy"]:
        if decoy in flag.lower():
            raise ValueError(f"Decoy flag rejected: {flag}")

    print(f"[+] Flag found: {flag}", flush=True)

    with open("flag.txt", "w") as f:
        f.write(flag.strip() + "\n")
    print("[+] Saved flag to flag.txt", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{U9X_UnP4ck1N6_B1n4Ri3S_ad49ff7a}
```
