#!/usr/bin/env python3
"""
Pitter, Patter, Platters (#87) - Automated Solver
Category: Forensics
Domain Archetype: Filesystem Artifacts & Metadata (Slack Space Steganography)

Extracts and reconstructs the hidden flag from Ext3 file slack space in suspicious.dd.sda1.
Reads connection parameters dynamically from connection.cfg.
Supports automated network asset acquisition via requests if image is absent.
"""

import os
import sys
import re
try:
    import requests
except ImportError:
    requests = None


def parse_config(cfg_path: str) -> dict:
    """Dynamically parses connection configuration parameters."""
    config = {"HOST": "", "PORT": 0, "URL": ""}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip().upper()
                    val = val.strip()
                    if key == "PORT":
                        try:
                            config[key] = int(val)
                        except ValueError:
                            config[key] = 0
                    else:
                        config[key] = val
    return config


def download_target_if_missing(image_path: str, url: str) -> None:
    """Fetches the disk image from network target if missing locally."""
    if os.path.exists(image_path):
        return

    if not url:
        print(f"[-] Target image {os.path.basename(image_path)} missing and no URL configured.", flush=True)
        sys.exit(1)

    print(f"[*] Downloading disk image from configured URL: {url}...", flush=True)
    if requests is not None:
        response = requests.get(url, stream=True, timeout=30)
        response.raise_for_status()
        with open(image_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=65536):
                if chunk:
                    f.write(chunk)
        print(f"[+] Download complete: {os.path.basename(image_path)} ({os.path.getsize(image_path)} bytes)", flush=True)
    else:
        import urllib.request
        urllib.request.urlretrieve(url, image_path)
        print(f"[+] Download complete via urllib: {os.path.basename(image_path)}", flush=True)


def inverse_transform(raw_slack: bytes) -> str:
    """
    Implements the inverse transformation operator (R o D_downarrow2):
    1. Decimates interleaved null padding bytes (D_downarrow2).
    2. Inverts the character sequence reflection (R).
    """
    # Step 1: Subsampling / decimation of null bytes
    decimated_chars = [chr(b) for b in raw_slack if b != 0]

    # Step 2: Reflection inversion (involution)
    reversed_candidate = "".join(decimated_chars)
    plaintext = reversed_candidate[::-1]
    return plaintext


def extract_closed_form(data: bytes, length: int = 33) -> str:
    """
    Closed-form coordinate extraction based on Ext3 block 2049 RAM slack:
    f_i = data[2098295 - 2*i] for i in range(33)
    """
    base_offset = 2098295
    if len(data) > base_offset:
        chars = [chr(data[base_offset - 2 * i]) for i in range(length)]
        return "".join(chars)
    return ""


def solve():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cfg_path = os.path.join(base_dir, "connection.cfg")
    config = parse_config(cfg_path)
    
    print(f"[*] Configuration loaded from {os.path.basename(cfg_path)}: {config}", flush=True)

    image_path = os.path.join(base_dir, "suspicious.dd.sda1")
    if not os.path.exists(image_path):
        download_target_if_missing(image_path, config.get("URL", ""))

    print(f"[*] Reading disk image: {os.path.basename(image_path)} ({os.path.getsize(image_path)} bytes)...", flush=True)
    with open(image_path, "rb") as f:
        data = f.read()

    # Method 1: Closed-form coordinate extraction
    closed_flag = extract_closed_form(data, length=33)
    print(f"[*] Closed-form candidate extraction: {closed_flag}", flush=True)

    # Method 2: Dynamic slack space boundary detection
    marker = b"Nothing to see here! But you may want to look here -->\n"
    idx = data.find(marker)
    if idx == -1:
        marker = b"Nothing to see here!"
        idx = data.find(marker)
        if idx == -1:
            print("[-] Error: Boundary anchor marker not found in disk image.", flush=True)
            sys.exit(1)

    print(f"[*] Identified logical container block anchor at offset {idx} (0x{idx:x})", flush=True)

    # Search for slack opening delimiter '}'
    brace_idx = data.find(b"}", idx)
    if brace_idx == -1:
        print("[-] Error: Slack space payload delimiter not found.", flush=True)
        sys.exit(1)

    print(f"[*] Slack space payload starts at offset {brace_idx} (0x{brace_idx:x})", flush=True)
    raw_slack = data[brace_idx:brace_idx + 128]
    dynamic_flag = inverse_transform(raw_slack)
    print(f"[*] Dynamic boundary reconstructed candidate: {dynamic_flag}", flush=True)

    # Validate candidate flag format against regex
    flag_pattern = re.compile(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})")
    match = flag_pattern.search(dynamic_flag) or flag_pattern.search(closed_flag)

    if not match:
        print("[-] Error: No valid flag pattern matching academy{...} or picoCTF{...} found.", flush=True)
        sys.exit(1)

    flag_token = match.group(1).strip()

    # Adversarial and decoy token filter
    decoys = ["decoy", "fake", "honeypot", "dummy", "not_the_flag"]
    if any(d in flag_token.lower() for d in decoys):
        print(f"[-] Error: Flag candidate '{flag_token}' matched decoy filter.", flush=True)
        sys.exit(1)

    print(f"[+] Successfully extracted and validated flag: {flag_token}", flush=True)

    # Persist flag to flag.txt
    flag_file = os.path.join(base_dir, "flag.txt")
    with open(flag_file, "w", encoding="utf-8") as f:
        f.write(flag_token + "\n")
    print(f"[+] Flag persisted to {os.path.basename(flag_file)}", flush=True)

    # Final stdout output
    print(flag_token, flush=True)
    return flag_token


if __name__ == "__main__":
    solve()
