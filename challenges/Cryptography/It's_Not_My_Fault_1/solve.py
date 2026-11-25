#!/usr/bin/env python3
import sys
import os
import re
import socket
import hashlib
import time
from pathlib import Path
from multiprocessing import Pool, cpu_count
import gmpy2

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 41063
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("HOST="):
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def pow_worker(args):
    prefix_bytes, target_bytes, start, count = args
    for i in range(start, start + count):
        candidate = prefix_bytes + str(i).encode()
        if hashlib.md5(candidate).digest()[-3:] == target_bytes:
            return candidate.decode()
    return None

def solve_pow(prefix, target_hex):
    print(f"[*] Solving PoW: prefix={prefix}, target_end={target_hex}...")
    workers = min(cpu_count() or 4, 16)
    target_bytes = bytes.fromhex(target_hex)
    chunk = 300_000
    base = 0
    t0 = time.time()
    with Pool(processes=workers) as pool:
        while True:
            tasks = [(prefix.encode(), target_bytes, base + i * chunk, chunk) for i in range(workers)]
            results = pool.map(pow_worker, tasks)
            for res in results:
                if res is not None:
                    print(f"[+] PoW solved in {time.time() - t0:.2f}s: {res}")
                    return res
            base += workers * chunk

def recv_until(sock, delimiter):
    buf = b""
    while delimiter not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="ignore")

def factor_n(n, e, max_bits=20):
    print(f"[*] Factoring n with e={e} (bits={max_bits})...")
    t0 = time.time()
    n = gmpy2.mpz(n)
    e = gmpy2.mpz(e)
    a = gmpy2.mpz(2)

    # d_p is coprime to p-1 (which is even), so d_p is strictly odd.
    # We step through odd numbers: cur = a^(i*e) mod n for i in 1, 3, 5, ...
    cur = gmpy2.powmod(a, e, n)
    step = gmpy2.powmod(a, 2 * e, n)
    batch = gmpy2.mpz(1)
    batch_size = 2000
    max_d = 1 << max_bits

    for i in range(1, max_d + 1, 2):
        diff = (cur - a) % n
        batch = (batch * diff) % n
        if (i // 2) % batch_size == 0 or i >= max_d - 1:
            factor = gmpy2.gcd(batch, n)
            if 1 < factor < n:
                elapsed = time.time() - t0
                print(f"[+] Found factor at step {i} in {elapsed:.2f}s: {factor}")
                return int(factor)
            elif factor == n:
                # Nontrivial fallback if batch contained n
                print("[*] Narrowing down factor within batch...")
                cur_test = gmpy2.powmod(a, max(1, i - 2 * batch_size) * e, n)
                for j in range(max(1, i - 2 * batch_size), i + 1, 2):
                    g = gmpy2.gcd((cur_test - a) % n, n)
                    if 1 < g < n:
                        print(f"[+] Found factor at step {j} in {time.time() - t0:.2f}s: {g}")
                        return int(g)
                    cur_test = (cur_test * step) % n
            batch = gmpy2.mpz(1)
        cur = (cur * step) % n

    # Fallback to checking all integers
    print("[-] Odd search did not find factor, trying all integers...")
    cur = gmpy2.powmod(a, e, n)
    step = cur
    batch = gmpy2.mpz(1)
    for i in range(1, max_d + 1):
        diff = (cur - a) % n
        batch = (batch * diff) % n
        if i % batch_size == 0 or i == max_d:
            factor = gmpy2.gcd(batch, n)
            if 1 < factor < n:
                print(f"[+] Found factor at step {i} in {time.time() - t0:.2f}s: {factor}")
                return int(factor)
            batch = gmpy2.mpz(1)
        cur = (cur * step) % n
    return None

def main():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    pow_prompt = recv_until(s, b"\n")
    print("[<] " + pow_prompt.strip())

    m = re.search(r'starts with "(\d+)" .*? these six hex digits: ([0-9a-fA-F]+)', pow_prompt)
    if not m:
        print("[-] Could not parse PoW prompt!")
        sys.exit(1)

    prefix, target_hex = m.group(1), m.group(2)
    solution = solve_pow(prefix, target_hex)
    s.sendall((solution + "\n").encode())

    # Receive Public Modulus and Clue
    response = recv_until(s, b"Clue : ")
    response += recv_until(s, b"\n")
    print("[<] Received Modulus & Clue:\n" + response.strip())

    n_match = re.search(r'Public Modulus\s*:\s*(\d+)', response)
    e_match = re.search(r'Clue\s*:\s*(\d+)', response)

    if not n_match or not e_match:
        print("[-] Could not parse n or e!")
        sys.exit(1)

    n = int(n_match.group(1))
    e = int(e_match.group(1))

    factor = factor_n(n, e, 20)
    if not factor:
        print("[-] Factoring failed!")
        sys.exit(1)

    p = factor
    q = n // p
    ans = p + q
    print(f"[*] Sending p + q = {ans}")
    s.sendall((str(ans) + "\n").encode())

    final_resp = recv_until(s, b"\n")
    print("[<] Final response:", final_resp.strip())

    flag_match = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', final_resp)
    if not flag_match:
        # Check if more data is coming
        s.settimeout(2.0)
        try:
            more = s.recv(4096).decode(errors="ignore")
            final_resp += more
            flag_match = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', final_resp)
        except Exception:
            pass

    if flag_match:
        flag = flag_match.group(1)
        print(f"\n[+] FLAG: {flag}\n")
        with open("flag.txt", "w") as f:
            f.write(flag + "\n")
    else:
        print("[-] Flag not found in output:", final_resp)

    s.close()

if __name__ == "__main__":
    main()
