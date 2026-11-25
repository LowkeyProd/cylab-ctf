#!/usr/bin/env python3
"""
Solve script for timer (#381)
Category: Reverse Engineering
"""
import os
import re
import zipfile
from pathlib import Path

def parse_connection_cfg(cfg_path="connection.cfg"):
    config = {}
    p = Path(cfg_path)
    if p.exists():
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    return config

def solve():
    print("[*] Solving timer...", flush=True)
    cfg = parse_connection_cfg()

    apk_path = Path("timer.apk")
    if not apk_path.exists():
        raise FileNotFoundError(f"{apk_path} not found.")

    flag = None
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            data = z.read(name)
            matches = re.findall(rb"(?:academy|picoCTF)\{[^\}]+\}", data)
            for m in matches:
                cand = m.decode("utf-8", errors="ignore")
                # Reject decoys
                lower_cand = cand.lower()
                if any(decoy in lower_cand for decoy in ["decoy", "fake", "honey", "not_the_flag", "dummy"]):
                    continue
                flag = cand
                print(f"[+] Found candidate flag in {name}: {flag}", flush=True)
                break
            if flag:
                break

    if not flag:
        raise ValueError("Flag could not be extracted from APK.")

    # Save to flag.txt
    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag.strip())

    print(f"[+] Flag written to flag.txt: {flag}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
