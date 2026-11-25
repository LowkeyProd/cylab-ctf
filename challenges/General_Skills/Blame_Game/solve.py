#!/usr/bin/env python3
"""
Solve script for Blame Game (#405)
Category: General Skills
"""
import os
import re
import subprocess
import zipfile
from pathlib import Path
import urllib.request

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("URL=") and line.split("=", 1)[1]:
                return line.split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/31eae587db829288524ad2f1581ec980aca2ad5f7e66908a5178390d1407cec5/challenge.zip"

def solve():
    base_dir = Path(__file__).resolve().parent
    drop_in_dir = base_dir / "drop-in"

    if not drop_in_dir.exists() or not (drop_in_dir / ".git").exists():
        zip_path = base_dir / "challenge.zip"
        if not zip_path.exists():
            url = get_target_url()
            print(f"[*] Downloading challenge zip from: {url}", flush=True)
            urllib.request.urlretrieve(url, zip_path)
        print("[*] Extracting challenge.zip...", flush=True)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(base_dir)

    print("[*] Running git blame on drop-in/message.py...", flush=True)
    res = subprocess.run(
        ["git", "blame", "message.py"],
        cwd=str(drop_in_dir),
        capture_output=True,
        text=True,
        check=True
    )

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    matches = flag_pattern.findall(res.stdout)

    if not matches:
        # Fallback to git log
        print("[*] Checking git log...", flush=True)
        res_log = subprocess.run(
            ["git", "log", "-p"],
            cwd=str(drop_in_dir),
            capture_output=True,
            text=True,
            check=True
        )
        matches = flag_pattern.findall(res_log.stdout)

    for flag in matches:
        if any(decoy in flag.lower() for decoy in ['fake', 'decoy', 'honey', 'not_the_flag', 'dummy']):
            continue
        print(f"[+] Flag found: {flag}", flush=True)
        flag_file = base_dir / "flag.txt"
        flag_file.write_text(flag.strip() + "\n")
        return flag

    print("[-] Flag not found.", flush=True)
    return None

if __name__ == "__main__":
    solve()
