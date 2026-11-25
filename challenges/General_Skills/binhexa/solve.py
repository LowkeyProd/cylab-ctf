#!/usr/bin/env python3
"""
Solve script for binhexa (#404)
Category: General Skills
"""
import re
import socket
import sys
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 43796
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("HOST="chatelaine.cylabacademy.net"
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def recv_until(sock, endings):
    buf = ""
    while True:
        c = sock.recv(1).decode("utf-8", errors="ignore")
        if not c:
            break
        buf += c
        for ending in endings:
            if buf.endswith(ending):
                return buf
    return buf

def is_valid_flag(flag_candidate):
    if not flag_candidate:
        return False
    lower = flag_candidate.lower()
    for decoy in ["decoy", "fake", "honeypot", "dummy", "not_the_flag"]:
        if decoy in lower:
            return False
    return True

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # Read initial welcome banner and first prompt
    data = recv_until(sock, ["Enter the binary result: ", "Enter the results of the last operation in hexadecimal: "])
    print(data, flush=True)

    m1 = re.search(r"Binary Number 1:\s*([01]+)", data)
    m2 = re.search(r"Binary Number 2:\s*([01]+)", data)
    if not m1 or not m2:
        raise ValueError("Failed to parse initial binary numbers!")
    
    b1 = m1.group(1)
    b2 = m2.group(1)
    n1 = int(b1, 2)
    n2 = int(b2, 2)
    print(f"[*] Parsed operands: Number 1 = {b1} ({n1}), Number 2 = {b2} ({n2})", flush=True)

    last_res = None

    # Handle 6 operations
    for q in range(1, 7):
        print(f"\n[*] Solving Question {q}/6...", flush=True)
        op_match = re.search(r"Operation \d+:\s*'([^']+)'", data)
        if not op_match:
            raise ValueError(f"Could not find operation for question {q} in:\n{data}")
        op = op_match.group(1)
        print(f"[*] Operation: {op}", flush=True)

        if op == '+':
            res = n1 + n2
        elif op == '*':
            res = n1 * n2
        elif op == '|':
            res = n1 | n2
        elif op == '&':
            res = n1 & n2
        elif op == '^':
            res = n1 ^ n2
        elif op == '<<':
            bits_match = re.search(r"by\s+(\d+)\s+bits", data)
            shift_bits = int(bits_match.group(1)) if bits_match else 1
            if "Binary Number 2" in data:
                res = n2 << shift_bits
            else:
                res = n1 << shift_bits
        elif op == '>>':
            bits_match = re.search(r"by\s+(\d+)\s+bits", data)
            shift_bits = int(bits_match.group(1)) if bits_match else 1
            if "Binary Number 2" in data:
                res = n2 >> shift_bits
            else:
                res = n1 >> shift_bits
        else:
            raise ValueError(f"Unsupported operator: {op}")

        last_res = res
        ans_bin = bin(res)[2:]
        print(f"[*] Sending binary answer: {ans_bin}", flush=True)
        sock.sendall((ans_bin + "\n").encode())

        data = recv_until(sock, ["Enter the binary result: ", "Enter the results of the last operation in hexadecimal: "])
        print(data, flush=True)

    if "hexadecimal" in data:
        ans_hex = hex(last_res)[2:]
        print(f"[*] Sending hexadecimal answer: {ans_hex}", flush=True)
        sock.sendall((ans_hex + "\n").encode())
        
        # Read final response containing the flag
        final_data = ""
        while True:
            chunk = sock.recv(4096).decode("utf-8", errors="ignore")
            if not chunk:
                break
            final_data += chunk
            if "}" in final_data:
                break
        print(final_data, flush=True)
        sock.close()

        # Extract flag matching academy{...} or picoCTF{...}
        flag_match = re.search(r"((?:academy|picoCTF)\{[^\s\r\n\}]+\})", final_data)
        if flag_match:
            flag = flag_match.group(1)
            if is_valid_flag(flag):
                print(f"[+] Flag found: {flag}", flush=True)
                flag_file = Path(__file__).resolve().parent / "flag.txt"
                flag_file.write_text(flag)
                print(f"[+] Saved flag to {flag_file.name}", flush=True)
                return flag
            else:
                print(f"[-] Decoy flag rejected: {flag}", flush=True)
        else:
            print("[-] Flag not found in server response.", flush=True)

    sock.close()
    return None

if __name__ == "__main__":
    solve()
