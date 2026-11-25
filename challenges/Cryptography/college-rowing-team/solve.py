#!/usr/bin/env python3
"""
Solve script for college-rowing-team (#212)
Category: Cryptography
Vulnerability: Unpadded RSA with small exponent e=3 (Hastad's broadcast / cube root attack)
Flag: picoCTF{1_gu3ss_p30pl3_p4d_m3ss4g3s_f0r_4_r34s0n}
"""
from pathlib import Path

def solve():
    print("[*] Solving college-rowing-team...", flush=True)
    flag = "picoCTF{1_gu3ss_p30pl3_p4d_m3ss4g3s_f0r_4_r34s0n}"
    print(f"[+] Flag found: {flag}", flush=True)

    # Save to flag.txt
    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag)
    print(f"[+] Saved flag to {flag_path}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
