#!/usr/bin/env python3
"""
Solve script for Collaborative Development (#410)
Category: General Skills
"""
import os
import re
import zipfile
import subprocess
from pathlib import Path
import requests

def get_connection_config():
    cfg = {}
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line and "=" in line and not line.startswith("#"):
                key, val = line.split("=", 1)
                cfg[key.strip()] = val.strip()
    return cfg

def ensure_repo():
    base_dir = Path(__file__).resolve().parent
    repo_dir = base_dir / "drop-in"
    zip_path = base_dir / "challenge.zip"

    # If repo doesn't exist or git folder is missing, try extracting challenge.zip or downloading it
    if not (repo_dir / ".git").exists():
        if not zip_path.exists():
            cfg = get_connection_config()
            url = cfg.get("URL")
            if url:
                print(f"[*] Downloading challenge.zip from {url}...", flush=True)
                resp = requests.get(url, timeout=30)
                resp.raise_for_status()
                zip_path.write_bytes(resp.content)
            else:
                raise RuntimeError("No challenge.zip found and no URL in connection.cfg")

        print("[*] Extracting challenge.zip...", flush=True)
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(base_dir)

    return repo_dir

def solve():
    repo_dir = ensure_repo()
    print(f"[*] Git repo directory: {repo_dir}", flush=True)

    # List branches matching feature/part-*
    cmd = ["git", "branch", "-a"]
    proc = subprocess.run(cmd, cwd=repo_dir, capture_output=True, text=True, check=True)
    branch_lines = proc.stdout.splitlines()

    feature_branches = []
    for line in branch_lines:
        b = line.replace("*", "").strip()
        if "feature/part-" in b:
            # strip remote prefixes if any
            clean_b = b.split("/")[-2] + "/" + b.split("/")[-1] if "remotes/" in b else b
            if clean_b not in feature_branches:
                feature_branches.append(clean_b)

    feature_branches.sort()
    print(f"[*] Found branches: {feature_branches}", flush=True)

    flag_pieces = []
    for branch in feature_branches:
        show_cmd = ["git", "show", f"{branch}:flag.py"]
        res = subprocess.run(show_cmd, cwd=repo_dir, capture_output=True, text=True, check=True)
        content = res.stdout
        # Extract string literals inside print
        # Typical format: print("academy{t3@mw0rk_", end='')
        # or print("m@k3s_th3_dr3@m_", end='')
        # or print("w0rk_f92d3827}")
        matches = re.findall(r'print\(["\'](.*?)["\']', content)
        for m in matches:
            if m and m != "Printing the flag...":
                flag_pieces.append(m)

    assembled_flag = "".join(flag_pieces)
    print(f"[*] Assembled string: {assembled_flag}", flush=True)

    flag_match = re.search(r'(?:academy|picoCTF)\{[^}]+\}', assembled_flag)
    if not flag_match:
        # Fallback regex search on the raw concatenated outputs
        flag_match = re.search(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}', assembled_flag)

    if flag_match:
        flag = flag_match.group(0)
        # Check against decoys
        for decoy in ['decoy', 'fake', 'honeypot', 'dummy']:
            if decoy in flag.lower():
                print(f"[-] Decoy detected: {flag}", flush=True)
                return None

        print(f"[+] Flag found: {flag}", flush=True)
        flag_file = Path(__file__).resolve().parent / "flag.txt"
        flag_file.write_text(flag + "\n")
        return flag
    else:
        print("[-] Could not parse flag", flush=True)
        return None

if __name__ == "__main__":
    solve()
