#!/usr/bin/env python3
"""
Solve script for MY GIT (#764)
Category: General Skills
"""
import os
import re
import sys
import shutil
import tempfile
import subprocess
from pathlib import Path


def load_config(config_path="connection.cfg"):
    cfg = {}
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    return cfg


def solve():
    print("[*] Solving MY GIT...", flush=True)

    base_dir = Path(__file__).parent.resolve()
    cfg = load_config(base_dir / "connection.cfg")

    host = cfg.get("HOST", "chatelaine.cylabacademy.net")
    port = cfg.get("PORT", "27334")
    url = cfg.get("URL") or f"ssh://git@{host}:{port}/git/challenge.git"

    # Password token from challenge description
    password = "e7273499"

    print(f"[*] Target Git URL: {url}", flush=True)

    # Setup askpass script
    askpass_path = base_dir / "askpass.bat"
    with open(askpass_path, "w", encoding="utf-8") as f:
        f.write(f"@echo {password}\n")

    env = os.environ.copy()
    env["GIT_ASKPASS"] = str(askpass_path)
    env["SSH_ASKPASS"] = str(askpass_path)
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env["GIT_SSH_COMMAND"] = "ssh -o StrictHostKeyChecking=no"

    flag = ""
    temp_dir = tempfile.mkdtemp(prefix="mygit_")

    try:
        repo_dir = os.path.join(temp_dir, "repo")
        print(f"[*] Cloning repository into {repo_dir}...", flush=True)
        res = subprocess.run(
            ["git", "clone", url, repo_dir],
            env=env,
            capture_output=True,
            text=True,
            timeout=30
        )
        if res.returncode != 0:
            print(f"[-] Clone failed: {res.stderr}", flush=True)
            return ""

        print("[*] Configuring committer as root <root@academy>...", flush=True)
        subprocess.run(["git", "-C", repo_dir, "config", "user.name", "root"], check=True)
        subprocess.run(["git", "-C", repo_dir, "config", "user.email", "root@academy"], check=True)

        flag_path = os.path.join(repo_dir, "flag.txt")
        with open(flag_path, "w", encoding="utf-8") as f:
            f.write(f"request flag {os.urandom(8).hex()}\n")

        subprocess.run(["git", "-C", repo_dir, "add", "flag.txt"], check=True)
        subprocess.run(["git", "-C", repo_dir, "commit", "-m", "update flag.txt"], check=True)

        print("[*] Pushing to remote to trigger git hook...", flush=True)
        push_res = subprocess.run(
            ["git", "-C", repo_dir, "push", "origin"],
            env=env,
            capture_output=True,
            text=True,
            timeout=30
        )

        combined_output = push_res.stdout + "\n" + push_res.stderr
        print("[*] Push output:\n" + combined_output, flush=True)

        matches = re.findall(r"(?:academy|picoCTF)\{[^}\s]+\}", combined_output)
        for cand in matches:
            cand_lower = cand.lower()
            if not any(d in cand_lower for d in ["decoy", "fake", "honeypot", "dummy"]):
                flag = cand
                break

    finally:
        # Clean up temp dir and askpass
        shutil.rmtree(temp_dir, ignore_errors=True)
        if askpass_path.exists():
            askpass_path.unlink()

    if flag:
        flag_out = base_dir / "flag.txt"
        with open(flag_out, "w", encoding="utf-8") as f:
            f.write(flag + "\n")
        print(f"[+] Flag found and saved to {flag_out}: {flag}", flush=True)
    else:
        print("[-] Flag not found in push output.", flush=True)

    return flag


if __name__ == "__main__":
    solve()
