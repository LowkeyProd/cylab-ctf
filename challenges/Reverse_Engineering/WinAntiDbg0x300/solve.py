#!/usr/bin/env python3
import os
import sys

def read_connection_cfg(cfg_path="connection.cfg"):
    cfg = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    return cfg

def popcount(n):
    return bin(n).count("1")

def compute_hash_round(buf):
    new_buf = list(buf)
    for i in range(len(buf)):
        pop = popcount(i % 255)
        new_buf[i] = ord('a') + ((new_buf[i] - ord('a') + pop) % 26)
    return new_buf

def solve():
    print("[*] Reading target configuration...", flush=True)
    cfg = read_connection_cfg()
    print(f"[*] Configuration: {cfg}", flush=True)

    config_path = "config.bin"
    if not os.path.exists(config_path):
        # Check if zip exists
        if os.path.exists("WinAntiDbg0x300.zip"):
            import zipfile
            print("[*] Extracting WinAntiDbg0x300.zip...", flush=True)
            with zipfile.ZipFile("WinAntiDbg0x300.zip") as z:
                z.extractall(pwd=b"academy")

    print("[*] Reading config.bin...", flush=True)
    with open(config_path, "rb") as f:
        data = f.read()

    length = int.from_bytes(data[:4], "little")
    p1 = list(data[4 : 4 + length])
    # separator is 1 byte at index 4 + length
    p2 = list(data[4 + length + 1 : 4 + length + 1 + length])

    print(f"[*] Config length: {length}", flush=True)
    print(f"[*] Initial buffer (p1): {bytes(p1).decode('ascii', errors='replace')}", flush=True)

    # From static analysis:
    # 1. wWinMain: ComputeHash(3) -> 3 rounds
    # 2. wWinMain: ComputeHash(2) -> 2 rounds
    # 3. wWinMain: ComputeHash(2) -> 2 rounds
    # 4. ManageChild/Mutex: ComputeHash(1) -> 1 round
    # 5. Mutex not existing: ComputeHash(1) -> 1 round
    # 6. ThreadProc: ComputeHash(2) -> 2 rounds
    # 7. ThreadProc (post-loop): ComputeHash(1) -> 1 round
    # Total = 3 + 2 + 2 + 1 + 1 + 2 + 1 = 12 rounds
    cur = list(p1)
    target_rounds = 12

    for r in range(target_rounds):
        cur = compute_hash_round(cur)

    flag_bytes = bytes([b ^ k for b, k in zip(p2, cur)])
    flag = flag_bytes.decode("ascii")

    print(f"[+] Flag found: {flag}", flush=True)

    # Save to flag.txt
    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag.strip() + "\n")
    print("[+] Saved flag to flag.txt", flush=True)

    return flag

if __name__ == "__main__":
    solve()
