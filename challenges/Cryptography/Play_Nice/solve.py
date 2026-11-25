#!/usr/bin/env python3
"""
Clean, self-contained solver script for Play Nice (#114).
Implements the 6x6 Playfair inverse digraph substitution.
Dynamically reads connection parameters from connection.cfg.
Outputs unbuffered status messages throughout.
"""
import json
import os
import re
import socket
import sys
from pathlib import Path

# Target parameters (auto-updated by tooling or dynamically loaded from connection.cfg)
HOST = "chatelaine.cylabacademy.net"
PORT = 22515
SQUARE_SIZE = 6

def generate_square(alphabet: str) -> list[list[str]]:
    assert len(alphabet) == SQUARE_SIZE * SQUARE_SIZE, f"Alphabet length must be {SQUARE_SIZE * SQUARE_SIZE}"
    matrix = []
    for i in range(0, len(alphabet), SQUARE_SIZE):
        matrix.append(list(alphabet[i:i + SQUARE_SIZE]))
    return matrix

def get_index(letter: str, matrix: list[list[str]]) -> tuple[int, int]:
    for row in range(SQUARE_SIZE):
        for col in range(SQUARE_SIZE):
            if matrix[row][col] == letter:
                return (row, col)
    raise ValueError(f"Letter '{letter}' not found in key matrix")

def decrypt_pair(pair: str, matrix: list[list[str]]) -> str:
    p1 = get_index(pair[0], matrix)
    p2 = get_index(pair[1], matrix)

    if p1[0] == p2[0]:
        # Same row: shift left modulo SQUARE_SIZE
        c1 = (p1[1] - 1) % SQUARE_SIZE
        c2 = (p2[1] - 1) % SQUARE_SIZE
        return matrix[p1[0]][c1] + matrix[p2[0]][c2]
    elif p1[1] == p2[1]:
        # Same column: shift up modulo SQUARE_SIZE
        r1 = (p1[0] - 1) % SQUARE_SIZE
        r2 = (p2[0] - 1) % SQUARE_SIZE
        return matrix[r1][p1[1]] + matrix[r2][p2[1]]
    else:
        # Rectangle: swap columns (involution)
        return matrix[p1[0]][p2[1]] + matrix[p2[0]][p1[1]]

def decrypt_string(ciphertext: str, matrix: list[list[str]]) -> str:
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        plaintext += decrypt_pair(ciphertext[i:i + 2], matrix)
    return plaintext

def self_test():
    """Verify Playfair inverse algorithm against a synthetic test vector."""
    test_alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    matrix = generate_square(test_alphabet)
    test_plain = "helloworld1234"
    
    def enc_pair(pair, m):
        p1 = get_index(pair[0], m)
        p2 = get_index(pair[1], m)
        if p1[0] == p2[0]:
            return m[p1[0]][(p1[1] + 1) % SQUARE_SIZE] + m[p2[0]][(p2[1] + 1) % SQUARE_SIZE]
        elif p1[1] == p2[1]:
            return m[(p1[0] + 1) % SQUARE_SIZE][p1[1]] + m[(p2[0] + 1) % SQUARE_SIZE][p2[1]]
        else:
            return m[p1[0]][p2[1]] + m[p2[0]][p1[1]]

    test_enc = "".join(enc_pair(test_plain[i:i + 2], matrix) for i in range(0, len(test_plain), 2))
    decrypted = decrypt_string(test_enc, matrix)
    assert decrypted == test_plain, f"Decryption failed: {decrypted} != {test_plain}"
    print(f"[+] Self-test verified: '{test_plain}' -> '{test_enc}' -> '{decrypted}'", flush=True)

def get_target_conn() -> tuple[str, int]:
    base_dir = Path(__file__).resolve().parent
    cfg_file = base_dir / "connection.cfg"
    info_file = base_dir / "info.json"
    
    target_host, target_port = HOST, PORT

    if info_file.exists():
        try:
            data = json.loads(info_file.read_text(encoding="utf-8"))
            if data.get("target_host"):
                target_host = data["target_host"]
            if data.get("target_port") and int(data["target_port"]) > 0:
                target_port = int(data["target_port"])
        except Exception:
            pass

    if cfg_file.exists():
        for line in cfg_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k, v = k.strip(), v.strip()
            if k == "HOST" and v:
                target_host = v
            elif k == "PORT" and v:
                try:
                    val = int(v)
                    if val > 0:
                        target_port = val
                except ValueError:
                    pass

    return target_host, target_port

def solve():
    self_test()

    if "--test-only" in sys.argv:
        return

    target_host, target_port = get_target_conn()
    print(f"[*] Target endpoint: {target_host}:{target_port}", flush=True)

    try:
        print(f"[*] Establishing connection to {target_host}:{target_port}...", flush=True)
        s = socket.create_connection((target_host, target_port), timeout=10)
    except Exception as e:
        print(f"[-] Connection failed ({e}). Check if remote container is running.", flush=True)
        return

    try:
        raw_banner = ""
        while "What is the plaintext message?" not in raw_banner:
            chunk = s.recv(4096).decode("utf-8", errors="ignore")
            if not chunk:
                break
            raw_banner += chunk

        print(f"[*] Banner received:\n{raw_banner}", flush=True)

        m_alpha = re.search(r"Here is the alphabet:\s*([^\r\n]+)", raw_banner)
        m_enc = re.search(r"Here is the encrypted message:\s*([^\r\n]+)", raw_banner)

        if not m_alpha or not m_enc:
            print("[-] Unable to extract alphabet or ciphertext from banner", flush=True)
            return

        alphabet = m_alpha.group(1).strip()
        enc_msg = m_enc.group(1).strip()

        print(f"[*] Alphabet ({len(alphabet)} chars): {alphabet}", flush=True)
        print(f"[*] Ciphertext ({len(enc_msg)} chars): {enc_msg}", flush=True)

        matrix = generate_square(alphabet)
        dec_msg = decrypt_string(enc_msg, matrix)
        print(f"[*] Decrypted plaintext: {dec_msg}", flush=True)

        print("[*] Submitting decrypted plaintext to service...", flush=True)
        s.sendall((dec_msg + "\n").encode("utf-8"))

        response = ""
        while True:
            chunk = s.recv(4096).decode("utf-8", errors="ignore")
            if not chunk:
                break
            response += chunk
            if "Congratulations!" in response or "{" in response:
                break

        print(f"[*] Server response:\n{response}", flush=True)

        flag_match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", response)
        if flag_match:
            flag = flag_match.group(1)
        else:
            flag_match2 = re.search(r"Here's the flag:\s*([^\r\n]+)", response)
            if flag_match2:
                flag = flag_match2.group(1).strip()
            else:
                flag = response.strip()

        print(f"[+] Flag extracted: {flag}", flush=True)
        flag_path = Path(__file__).resolve().parent / "flag.txt"
        flag_path.write_text(flag, encoding="utf-8")
        print(f"[*] Saved flag to {flag_path}", flush=True)

    finally:
        s.close()

if __name__ == "__main__":
    solve()
