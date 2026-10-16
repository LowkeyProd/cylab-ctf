#!/usr/bin/env python3
"""
WebNet1 Solution Script
Extracts decrypted HTTP objects using tshark and TLS private key,
then searches for the flag in exported assets (vulture.jpg Exif metadata).
"""

import os
import re
import shutil
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_FILE = os.path.join(BASE_DIR, "webnet1-capture.pcap")
KEY_FILE = os.path.join(BASE_DIR, "picopico.key")
OUTPUT_DIR = os.path.join(BASE_DIR, "exported_objects")
FLAG_FILE = os.path.join(BASE_DIR, "flag.txt")


def find_tshark():
    tshark = shutil.which("tshark")
    if tshark:
        return tshark
    common_paths = [
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
    ]
    for p in common_paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    raise RuntimeError("tshark binary not found on the system.")


def solve():
    tshark = find_tshark()

    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Export HTTP objects using tshark and RSA private key
    # Option: uat:rsa_keys:"\"<keyfile>\",\"<password>\""
    cmd = [
        tshark,
        "-r",
        PCAP_FILE,
        "-o",
        f'uat:rsa_keys:"{KEY_FILE}",""',
        "--export-objects",
        f"http,{OUTPUT_DIR}",
    ]

    subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )

    pattern = re.compile(rb"(academy\{[^}]+\}|picoCTF\{[^}]+\})")
    fake_flag = b"academy{this.is.not.your.flag.anymore}"
    flag = None

    for root, _, files in os.walk(OUTPUT_DIR):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            with open(fpath, "rb") as f:
                content = f.read()
                matches = pattern.findall(content)
                for match in matches:
                    if match != fake_flag:
                        flag = match.decode("utf-8")
                        break
            if flag:
                break

    if not flag:
        raise ValueError("Flag not found in exported objects.")

    with open(FLAG_FILE, "w") as f:
        f.write(flag + "\n")

    print(f"Flag found: {flag}")
    return flag


if __name__ == "__main__":
    solve()
