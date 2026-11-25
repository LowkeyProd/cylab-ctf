#!/usr/bin/env python3
"""
Solve script for Hidden Cipher 1
Challenge ID: 745
Category: Reverse Engineering
"""
import re
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 32547
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("HOST=") and line.split("=", 1)[1]:
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def decrypt_ciphertext(hex_cipher: str, key: bytes = b"S3Cr3t") -> str:
    ciphertext = bytes.fromhex(hex_cipher.strip())
    plaintext = bytes([b ^ key[i % len(key)] for i, b in enumerate(ciphertext)])
    return plaintext.decode("latin1", errors="ignore")

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))

    raw_data = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            raw_data += chunk
            if b"\n" in chunk and b"encrypted flag" in raw_data:
                break
        except socket.timeout:
            break
    s.close()

    text = raw_data.decode(errors="ignore").strip()
    print(f"[*] Received response:\n{text}", flush=True)

    # Extract hex string
    match = re.search(r"([0-9a-fA-F]{16,})", text)
    if not match:
        raise ValueError(f"Could not find hex ciphertext in output: {text}")

    hex_cipher = match.group(1)
    print(f"[*] Hex ciphertext: {hex_cipher}", flush=True)

    flag_candidate = decrypt_ciphertext(hex_cipher)
    print(f"[*] Decrypted candidate: {flag_candidate}", flush=True)

    # Validate flag format
    flag_match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", flag_candidate)
    if not flag_match:
        raise ValueError(f"No valid flag pattern found in: {flag_candidate}")

    flag = flag_match.group(1)
    for decoy in ["decoy", "fake", "honeypot", "dummy"]:
        if decoy in flag.lower():
            raise ValueError(f"Decoy flag rejected: {flag}")

    print(f"[+] Flag found: {flag}", flush=True)

    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag)
    print(f"[+] Saved flag to {flag_file}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
