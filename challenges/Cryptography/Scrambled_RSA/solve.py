#!/usr/bin/env python3
import socket
import string
import sys
import time
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 33727
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("HOST="):
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT="):
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def read_until(s, delim):
    buf = b""
    while not buf.endswith(delim):
        c = s.recv(1)
        if not c:
            break
        buf += c
    return buf

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)
    s = socket.create_connection((host, port), timeout=30)

    header = read_until(s, b"I will encrypt whatever you give me: ")
    lines = header.decode(errors="ignore").splitlines()
    flag_c = ""
    for line in lines:
        if line.startswith("flag: "):
            flag_c = line.split("flag: ", 1)[1].strip()
        elif line.startswith("e: "):
            print(f"[*] {line}", flush=True)

    print(f"[*] flag_c length: {len(flag_c)} digits", flush=True)

    def get_enc(txt):
        s.sendall(txt.encode() + b"\n")
        read_until(s, b"Here you go: ")
        ans = read_until(s, b"\n").strip()
        read_until(s, b"I will encrypt whatever you give me: ")
        return ans.decode()

    # Pre-populate known prefix: academy{
    prefix = "academy{"
    known_chunks = []
    cur = ""
    print(f"[*] Initializing prefix '{prefix}'...", flush=True)
    for ch in prefix:
        cur += ch
        enc = get_enc(cur)
        rem = enc
        for c in known_chunks:
            rem = rem.replace(c, "")
        if rem not in flag_c:
            print(f"[!] Warning: Chunk for '{ch}' at index {len(known_chunks)} not in flag_c!", flush=True)
        known_chunks.append(rem)
        print(f"[*] Pos {len(known_chunks)-1}: '{ch}' (chunk len {len(rem)})", flush=True)

    flag = prefix
    charset = string.ascii_lowercase + string.digits + "_-}" + string.ascii_uppercase

    while not flag.endswith("}"):
        pos = len(flag)
        found = False
        print(f"[*] Searching for character at position {pos}...", flush=True)
        for ch in charset:
            cand = flag + ch
            enc = get_enc(cand)
            rem = enc
            for c in known_chunks:
                rem = rem.replace(c, "")
            if rem in flag_c:
                flag += ch
                known_chunks.append(rem)
                found = True
                print(f"[+] Found character at pos {pos}: '{ch}' -> Current flag: {flag}", flush=True)
                break
        if not found:
            print(f"[-] Failed to find character at pos {pos} with standard charset, trying all printable ASCII...", flush=True)
            for ch in string.printable:
                if ch in charset or ch in "\r\n":
                    continue
                cand = flag + ch
                enc = get_enc(cand)
                rem = enc
                for c in known_chunks:
                    rem = rem.replace(c, "")
                if rem in flag_c:
                    flag += ch
                    known_chunks.append(rem)
                    found = True
                    print(f"[+] Found character at pos {pos}: '{ch}' -> Current flag: {flag}", flush=True)
                    break
            if not found:
                print(f"[!] Could not determine character at pos {pos}. Aborting.", flush=True)
                break

    s.close()

    print(f"\n[+] Full Flag Recovered: {flag}", flush=True)
    flag_path = Path(__file__).resolve().parent / "flag.txt"
    flag_path.write_text(flag.strip() + "\n")
    print(f"[*] Flag written to {flag_path}", flush=True)

if __name__ == "__main__":
    solve()
