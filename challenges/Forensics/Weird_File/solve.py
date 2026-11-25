#!/usr/bin/env python3
import os
import re
import sys
import base64
import zipfile
import urllib.request

def parse_connection_cfg(cfg_path="connection.cfg"):
    config = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    return config

def main():
    config = parse_connection_cfg()
    target_file = "weird.docm"

    # If weird.docm is not present locally, download from URL in connection.cfg
    if not os.path.exists(target_file):
        url = config.get("URL")
        if url:
            print(f"Downloading {target_file} from {url}...", flush=True)
            urllib.request.urlretrieve(url, target_file)
        else:
            print(f"Error: {target_file} not found and no URL configured.", flush=True)
            sys.exit(1)

    print(f"Analyzing {target_file}...", flush=True)
    flag = None

    with zipfile.ZipFile(target_file, "r") as z:
        for name in z.namelist():
            data = z.read(name)
            # Find base64 strings
            b64_matches = re.findall(rb"[A-Za-z0-9+/]{16,}={0,2}", data)
            for b64 in b64_matches:
                try:
                    decoded = base64.b64decode(b64).decode("utf-8", errors="ignore")
                    flag_match = re.search(r"(?:academy|picoCTF)\{[^}]+\}", decoded)
                    if flag_match:
                        candidate = flag_match.group(0)
                        if not any(decoy in candidate.lower() for decoy in ["decoy", "fake", "honey", "dummy"]):
                            flag = candidate
                            break
                except Exception:
                    pass
            if flag:
                break

    if not flag:
        print("Flag not found in document!", flush=True)
        sys.exit(1)

    print(f"Found Flag: {flag}", flush=True)
    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag)

    print(flag, flush=True)

if __name__ == "__main__":
    main()
