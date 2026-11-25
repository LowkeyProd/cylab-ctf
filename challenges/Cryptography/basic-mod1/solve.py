#!/usr/bin/env python3
"""
Solve script for basic-mod1 (#253)
Category: Cryptography
"""
from pathlib import Path
import string

def solve():
    print("[*] Solving basic-mod1...", flush=True)
    message_file = Path(__file__).parent / "message.txt"
    with open(message_file, "r") as f:
        content = f.read().strip()
    
    numbers = [int(x) for x in content.split()]
    
    # 0-25 is uppercase alphabet, 26-35 are digits 0-9, 36 is underscore
    charset = string.ascii_uppercase + string.digits + "_"
    
    decrypted = "".join(charset[n % 37] for n in numbers)
    flag = f"academy{{{decrypted}}}"
    
    print(f"[+] Flag found: {flag}", flush=True)
    
    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag)
    print(f"[+] Saved flag to {flag_path}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
