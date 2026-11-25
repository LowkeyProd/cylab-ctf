#!/usr/bin/env python3
"""
Solve script for Commitment Issues (#411)
Category: General Skills
"""
import os
import re
import sys
import zipfile
import subprocess
from pathlib import Path

def get_connection_config():
    cfg = {}
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg

def ensure_repo():
    cur_dir = Path(__file__).resolve().parent
    repo_dir = cur_dir / "drop-in"
    if repo_dir.exists() and (repo_dir / ".git").exists():
        return repo_dir

    zip_path = cur_dir / "challenge.zip"
    if not zip_path.exists():
        cfg = get_connection_config()
        url = cfg.get("URL")
        if url:
            print(f"[*] Downloading challenge.zip from {url}...", flush=True)
            import requests
            r = requests.get(url, timeout=30)
            r.raise_for_status()
            zip_path.write_bytes(r.content)
            print("[+] Download complete.", flush=True)

    if zip_path.exists():
        print("[*] Extracting challenge.zip...", flush=True)
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(cur_dir)

    if repo_dir.exists() and (repo_dir / ".git").exists():
        return repo_dir
    return None

def find_flag_in_git(repo_dir: Path):
    cmd = ["git", "-C", str(repo_dir), "log", "-p", "--all"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = res.stdout
    except Exception as e:
        print(f"[-] git log error: {e}", flush=True)
        return None

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    matches = flag_pattern.findall(output)
    for match in matches:
        lower_match = match.lower()
        if any(decoy in lower_match for decoy in ['decoy', 'fake', 'honeypot', 'dummy']):
            continue
        return match
    return None

def main():
    repo_dir = ensure_repo()
    if not repo_dir:
        print("[-] Could not find or extract git repository.", flush=True)
        sys.exit(1)

    print(f"[*] Inspecting git history in {repo_dir}...", flush=True)
    flag = find_flag_in_git(repo_dir)

    if flag:
        print(f"[+] Flag found: {flag}", flush=True)
        out_file = Path(__file__).resolve().parent / "flag.txt"
        out_file.write_text(flag.strip() + "\n", encoding="utf-8")
        print(f"[+] Saved flag to {out_file}", flush=True)
    else:
        print("[-] Flag not found in git history.", flush=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
