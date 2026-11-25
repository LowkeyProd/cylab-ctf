#!/usr/bin/env python3
"""
Solve script for waves over lambda (#38)
"""
import re
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 12824
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

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))
    
    data = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"---" in data and data.count(b"---") >= 2:
                # got the header section
                break
        except Exception:
            break
    s.close()
    
    text = data.decode("utf-8", errors="ignore")
    print("[*] Received server message:", flush=True)
    print(text, flush=True)
    
    # Extract line between dashes
    # e.g. "khxitzec jsts rc fhpt auzi - atsdpsxkf_rc_k_host_uzqmbz_tjotamefjo"
    # Plaintext: "congrats here is your flag - frequency_is_c_over_lambda_..."
    lines = [line.strip() for line in text.splitlines() if line.strip() and not set(line.strip()).issubset({'-', '='})]
    if not lines:
        raise ValueError("Could not find message lines")
    
    header = lines[0]
    print(f"[*] Analyzing header: {header}", flush=True)
    
    # Header format:
    # <congrats> <here> <is> <your> <flag> - <frequency>_<is>_<c>_<over>_<lambda>_<suffix>
    match = re.search(r'([a-z]+)\s+([a-z]+)\s+([a-z]+)\s+([a-z]+)\s+([a-z]+)\s*-\s*([a-z]+)_([a-z]+)_([a-z]+)_([a-z]+)_([a-z]+)_([a-z]+)', header)
    if not match:
        raise ValueError(f"Header pattern mismatch: {header}")
    
    c_congrats, c_here, c_is, c_your, c_flag, c_freq, c_is2, c_c, c_over, c_lambda, c_suffix = match.groups()
    
    mapping = {}
    def learn(cipher_word, plain_word):
        for c, p in zip(cipher_word, plain_word):
            if c in mapping and mapping[c] != p:
                raise ValueError(f"Conflict in mapping: {c} maps to {mapping[c]} and {p}")
            mapping[c] = p
            
    learn(c_congrats, "congrats")
    learn(c_here, "here")
    learn(c_is, "is")
    learn(c_your, "your")
    learn(c_flag, "flag")
    learn(c_freq, "frequency")
    learn(c_is2, "is")
    learn(c_c, "c")
    learn(c_over, "over")
    learn(c_lambda, "lambda")
    
    print(f"[*] Recovered partial alphabet substitution ({len(mapping)} letters):", flush=True)
    for c in sorted(mapping):
        print(f"    {c} -> {mapping[c]}", flush=True)
        
    decrypted_suffix = "".join(mapping.get(c, "?") for c in c_suffix)
    if "?" in decrypted_suffix:
        raise ValueError(f"Unmapped characters in suffix: {decrypted_suffix}")
    
    flag = f"frequency_is_c_over_lambda_{decrypted_suffix}"
    print(f"[+] Flag found: {flag}", flush=True)
    
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag)
    print(f"[+] Saved flag to {flag_file}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
