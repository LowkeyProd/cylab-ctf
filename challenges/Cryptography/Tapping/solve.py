#!/usr/bin/env python3
"""
Solve script for Tapping (#21)
Target configured via connection.cfg
"""
import re
import socket
from pathlib import Path

MORSE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9'
}

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 32078
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

def decode_morse(morse_code: str) -> str:
    tokens = morse_code.strip().split()
    decoded = []
    for token in tokens:
        if token in MORSE_DICT:
            decoded.append(MORSE_DICT[token])
        elif token in "{}":
            decoded.append(token)
        else:
            decoded.append(token)
    return "".join(decoded)

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)
    sock.connect((host, port))

    raw_data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw_data += chunk
        except socket.timeout:
            break
    sock.close()

    text = raw_data.decode(errors="ignore").strip()
    print(f"[*] Received raw data:\n{text}", flush=True)

    decoded = decode_morse(text)
    print(f"[*] Decoded morse:\n{decoded}", flush=True)

    # Format flag as academy{...}
    # Decoded text is likely ACADEMY{...} or academy{...} or PICOCTF{...}
    match = re.search(r'(ACADEMY|PICOCTF)?\{([^}]+)\}', decoded, re.IGNORECASE)
    if match:
        prefix = match.group(1) or "academy"
        flag = f"{prefix.lower()}{{{match.group(2)}}}"
    elif "{" in decoded and "}" in decoded:
        prefix, rest = decoded.split("{", 1)
        inner, _ = rest.split("}", 1)
        flag = f"academy{{{inner}}}"
    else:
        flag = decoded

    # Reject decoys
    for bad in ["fake", "decoy", "honey", "not_the_flag", "dummy"]:
        if bad in flag.lower():
            raise ValueError(f"Flag rejected as decoy: {flag}")

    print(f"[+] Flag extracted: {flag}", flush=True)

    flag_path = Path(__file__).resolve().parent / "flag.txt"
    flag_path.write_text(flag + "\n", encoding="utf-8")
    print(f"[+] Flag written to {flag_path}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
