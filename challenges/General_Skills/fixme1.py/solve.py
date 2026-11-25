#!/usr/bin/env python3
"""
Solve script for fixme1.py (#240)
Category: General Skills
"""
import subprocess
import re
from pathlib import Path

def solve():
    print("[*] Solving fixme1.py...", flush=True)
    res = subprocess.run(["python", "fixme1.py"], capture_output=True, text=True, check=True)
    out = res.stdout
    print(out, flush=True)
    
    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", out)
    if not match:
        raise ValueError("Flag pattern not found in output")
    
    flag = match.group(1)
    Path("flag.txt").write_text(flag, encoding="utf-8")
    print(f"[+] Flag found: {flag}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
