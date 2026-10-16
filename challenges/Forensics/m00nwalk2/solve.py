#!/usr/bin/env python3
"""
Automated Solver for m00nwalk2 (#28)
Extracts flag from message.wav using Steghide with password recovered from clue1.wav SSTV.
"""
import subprocess
import re
from pathlib import Path

def solve():
    base_dir = Path(__file__).resolve().parent
    message_file = base_dir / "message.wav"
    password = "hidden_stegosaurus"

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{base_dir}:/work",
        "-w", "/work",
        "local/steghide",
        "extract", "-sf", "message.wav", "-p", password, "-xf", "-"
    ]
    res = subprocess.run(cmd, capture_output=True, check=True)
    out = res.stdout.decode("latin1", errors="ignore")
    
    m = re.search(r'(academy\{[^\}]+\}|picoCTF\{[^\}]+\})', out)
    if not m:
        raise ValueError(f"Flag not found in output: {out}")
        
    flag = m.group(1)
    print(f"[+] Recovered Flag: {flag}")
    
    flag_file = base_dir / "flag.txt"
    flag_file.write_text(flag + "\n")
    return flag

if __name__ == "__main__":
    solve()
