#!/usr/bin/env python3
"""
Solve script for mus1c (#15)
Category: General Skills
"""
from pathlib import Path

def solve():
    print("[*] Solving mus1c...", flush=True)
    
    # Rockstar output numbers from mus1c-lyrics.txt:
    # 114, 114, 114, 111, 99, 107, 110, 114, 110, 48, 49, 49, 51, 114
    nums = [114, 114, 114, 111, 99, 107, 110, 114, 110, 48, 49, 49, 51, 114]
    decoded = "".join(chr(n) for n in nums)
    print(f"[*] Decoded string: {decoded}", flush=True)
    
    flag = f"academy{{{decoded}}}"
    print(f"[*] Flag: {flag}", flush=True)
    
    Path("flag.txt").write_text(flag)
    return flag

if __name__ == "__main__":
    solve()
