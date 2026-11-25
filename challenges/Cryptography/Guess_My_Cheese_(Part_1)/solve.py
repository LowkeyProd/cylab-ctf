#!/usr/bin/env python3
"""
Solve script for Guess My Cheese (Part 1) (#473)
Category: Cryptography
"""
import re
import socket
from pathlib import Path

def parse_connection_cfg(cfg_path=None):
    if cfg_path is None:
        cfg_path = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    path = Path(cfg_path)
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line:
                    key, val = line.split("=", 1)
                    config[key.strip()] = val.strip()
    return config

def recv_until(sock, target):
    buf = ""
    while target not in buf:
        chunk = sock.recv(1024).decode("latin1")
        if not chunk:
            break
        buf += chunk
    return buf

def solve():
    print("[*] Solving Guess My Cheese (Part 1)...")
    config = parse_connection_cfg()
    host = config.get("HOST", "xebec.cylabacademy.net")
    port = int(config.get("PORT", 26900))

    s = socket.socket()
    s.settimeout(15)
    s.connect((host, port))

    banner = recv_until(s, "What would you like to do?")
    m = re.search(r"Here's my secret cheese -- if you're Squeexy, you'll be able to guess it:\s+([A-Za-z]+)", banner)
    if not m:
        raise ValueError("Could not find secret cheese in banner")
    secret_cheese_enc = m.group(1).strip()
    print(f"[*] Encrypted secret cheese: {secret_cheese_enc}")

    # Query encryption oracle with known cheese 'cheddar'
    s.sendall(b"e\n")
    recv_until(s, "What cheese would you like to encrypt?")
    s.sendall(b"cheddar\n")
    enc_resp = recv_until(s, "What would you like to do?")

    m_enc = re.search(r"Here's your encrypted cheese:\s+([A-Za-z]+)", enc_resp)
    if not m_enc:
        raise ValueError("Could not extract encrypted cheddar")
    cheddar_enc = m_enc.group(1).strip().upper()
    print(f"[*] Encrypted 'cheddar': {cheddar_enc}")

    # 'cheddar' mapping:
    # index 5 is 'a' -> 0: E(0) = (a * 0 + b) mod 26 = b mod 26
    b = (ord(cheddar_enc[5]) - ord('A')) % 26
    # index 3 is 'd' -> 3: E(3) = (3 * a + b) mod 26
    d_val = (ord(cheddar_enc[3]) - ord('A')) % 26
    # 3 * a = (d_val - b) mod 26 => a = 9 * (d_val - b) mod 26 (since 3 * 9 = 27 = 1 mod 26)
    a = (9 * (d_val - b)) % 26
    print(f"[*] Recovered affine cipher keys: a = {a}, b = {b}")

    a_inv = pow(a, -1, 26)

    # Decrypt secret cheese
    decrypted_cheese = ""
    for ch in secret_cheese_enc.upper():
        if "A" <= ch <= "Z":
            y = ord(ch) - ord("A")
            x = (a_inv * (y - b)) % 26
            decrypted_cheese += chr(ord("a") + x)
        else:
            decrypted_cheese += ch

    print(f"[*] Decrypted secret cheese: {decrypted_cheese}")

    # Send guess
    s.sendall(b"g\n")
    recv_until(s, "So...what's my cheese?")
    s.sendall((decrypted_cheese + "\n").encode())

    # Receive final response
    full_output = ""
    while True:
        try:
            chunk = s.recv(4096).decode("latin1", errors="ignore")
            if not chunk:
                break
            full_output += chunk
            if "academy{" in full_output or "picoCTF{" in full_output:
                break
        except socket.timeout:
            break

    s.close()

    m_flag = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", full_output)
    if m_flag:
        flag = m_flag.group(1)
        print(f"[+] Found flag: {flag}")
        with open("flag.txt", "w", encoding="utf-8") as f:
            f.write(flag + "\n")
        return flag
    else:
        print("[-] Flag not found in response:\n", full_output)
        return ""

if __name__ == "__main__":
    solve()
