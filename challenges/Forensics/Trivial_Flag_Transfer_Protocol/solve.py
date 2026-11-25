#!/usr/bin/env python3
"""
Solve script for Trivial Flag Transfer Protocol (#103)
Extracts flag hidden using steghide in picture3.bmp with password DUEDILIGENCE
"""
import os
import subprocess
import codecs
import re

def get_connection_config():
    config = {}
    cfg_path = os.path.join(os.path.dirname(__file__), "connection.cfg")
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    config[k.strip()] = v.strip()
    return config

def rot13(text):
    return codecs.decode(text, "rot_13")

def solve():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    extracted_dir = os.path.join(base_dir, "extracted")
    
    # Read plan / instructions if present
    plan_path = os.path.join(extracted_dir, "plan")
    if os.path.exists(plan_path):
        with open(plan_path, "r", encoding="utf-8") as f:
            plan_text = f.read().strip()
            decoded_plan = rot13(plan_text)
            print(f"[+] Decoded plan: {decoded_plan}", flush=True)

    password = "DUEDILIGENCE"
    picture_path = os.path.join(extracted_dir, "picture3.bmp")
    flag_out_extracted = os.path.join(extracted_dir, "flag.txt")
    flag_out_root = os.path.join(base_dir, "flag.txt")

    # If flag.txt already exists and contains the flag, read it
    flag = None
    if os.path.exists(flag_out_extracted):
        with open(flag_out_extracted, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read().strip()
            match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", content)
            if match:
                flag = match.group(1)

    if not flag:
        # Run steghide via WSL
        wsl_extracted = "/mnt/" + extracted_dir[0].lower() + extracted_dir[2:].replace("\\", "/")
        cmd = f"wsl bash -c \"cd '{wsl_extracted}' && steghide extract -sf picture3.bmp -p {password} -f\""
        print(f"[+] Running extraction command: {cmd}", flush=True)
        subprocess.run(cmd, shell=True, check=True)

        if os.path.exists(flag_out_extracted):
            with open(flag_out_extracted, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
                match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", content)
                if match:
                    flag = match.group(1)

    if flag:
        with open(flag_out_root, "w", encoding="utf-8") as f:
            f.write(flag + "\n")
        print(f"[+] Extracted flag: {flag}", flush=True)
        print(flag, flush=True)
    else:
        print("[-] Flag not found!", flush=True)

if __name__ == "__main__":
    solve()
