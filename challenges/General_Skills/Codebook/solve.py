#!/usr/bin/env python3
"""
Solve script for Codebook (#238)
Category: General Skills
"""
from pathlib import Path
import code as challenge_code

def solve():
    print("[*] Solving Codebook...", flush=True)
    codebook_path = Path(__file__).parent / "codebook.txt"
    codebook = codebook_path.read_text(encoding="utf-8")
    
    password = (
        codebook[4] + codebook[14] + codebook[13] + codebook[14] +
        codebook[23] + codebook[25] + codebook[16] + codebook[0] +
        codebook[25]
    )
    flag = challenge_code.str_xor(challenge_code.flag_enc, password)
    print(f"[*] Recovered flag: {flag}", flush=True)

    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag.strip(), encoding="utf-8")
    print(f"[*] Flag written to {flag_path}", flush=True)
    return flag.strip()

if __name__ == "__main__":
    solve()
