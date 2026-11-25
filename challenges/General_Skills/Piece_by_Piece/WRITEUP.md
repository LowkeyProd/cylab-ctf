# Writeup: Piece by Piece

## Header & Metadata
- **Challenge:** Piece by Piece (ID: 740)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `academy{z1p_and_spl1t_f1l3s_4r3_fun_bbe0be9e}`

---

## Mô tả bài toán (Overview / Analysis)
After logging in, you will find multiple file parts in your home directory. These parts need to be combined and extracted to reveal the flag.
SSH to `xebec.cylabacademy.net`:`24979` and login as `ctf-player` with password `3854745b`.

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Piece by Piece (#740)
Category: General Skills
"""

import os
import re
import sys
from pathlib import Path
import paramiko

def parse_connection_cfg(cfg_path: Path):
    config = {}
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    return config

def solve():
    print("[*] Solving Piece by Piece...", flush=True)

    base_dir = Path(__file__).resolve().parent
    cfg_file = base_dir / "connection.cfg"
    config = parse_connection_cfg(cfg_file)

    host = config.get("HOST", "")
    port_str = config.get("PORT", "0")
    user = config.get("USER", "ctf-player")
    password = config.get("PASSWORD", "")

    # Fallback to info.json if connection.cfg lacks fields
    if not host or port_str == "0" or not password:
        info_file = base_dir / "info.json"
        if info_file.exists():
            import json
            try:
                with open(info_file, "r", encoding="utf-8") as f:
                    info_data = json.load(f)
                    desc = info_data.get("description", "")
                    # Extract SSH details
                    m = re.search(r'SSH to `?([a-zA-Z0-9\.\-]+)`?:`?(\d+)`?\s+and login as `?([a-zA-Z0-9\-_]+)`?\s+with password `?([a-zA-Z0-9\-_]+)`?', desc)
                    if m:
                        host = host or m.group(1)
                        port_str = port_str if port_str != "0" else m.group(2)
                        user = user or m.group(3)
                        password = password or m.group(4)
            except Exception as e:
                print(f"[-] Error reading info.json fallback: {e}", flush=True)

    port = int(port_str) if port_str and port_str != "0" else 22
    print(f"[*] Target: {user}@{host}:{port}", flush=True)

    if not host or not password:
        raise ValueError("Could not determine SSH target host or password.")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print("[*] Connecting via SSH...", flush=True)
    client.connect(host, port=port, username=user, password=password, timeout=15)
    print("[+] Connected successfully!", flush=True)

    # Remote command to concatenate file parts, extract password-protected zip, and print flag
    cmd = "cat part_a* > flag.zip && unzip -o -P supersecret flag.zip && cat flag.txt"
    print(f"[*] Executing remote extraction: {cmd}", flush=True)
    stdin, stdout, stderr = client.exec_command(cmd)

    output = stdout.read().decode(errors="replace")
    err_output = stderr.read().decode(errors="replace")
    client.close()

    print("[*] Command output:\n" + output, flush=True)
    if err_output:
        print("[!] Stderr:\n" + err_output, flush=True)

    # Search for flag pattern
    flag_match = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', output)
    if not flag_match:
        raise ValueError(f"Flag not found in command output: {output}")

    flag = flag_match.group(1).strip()

    # Reject decoys
    for decoy_word in ['fake', 'decoy', 'honey', 'not_the_flag', 'dummy']:
        if decoy_word in flag.lower():
            raise ValueError(f"Decoy flag rejected: {flag}")

    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = base_dir / "flag.txt"
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag + "\n")
    print(f"[+] Saved flag to {flag_path}", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{z1p_and_spl1t_f1l3s_4r3_fun_bbe0be9e}
```
