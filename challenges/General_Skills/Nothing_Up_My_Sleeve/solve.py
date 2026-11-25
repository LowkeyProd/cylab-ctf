#!/usr/bin/env python3
"""
Solve script for Nothing Up My Sleeve (#91)
Category: General Skills
"""
import re
from pathlib import Path

def solve():
    print("[*] Solving Nothing Up My Sleeve...", flush=True)
    flag_path = Path(__file__).parent / "flag.txt"
    if flag_path.exists():
        flag = flag_path.read_text(encoding="utf-8").strip()
    else:
        # Fallback if flag.txt is not yet downloaded
        import urllib.request
        url = "https://challenge-files.cylabacademy.net/library/7a2d73afcf61879089df15c526cb7c833947dd7fa6aeb074eeacf4eb6a5ce096/flag.txt"
        with urllib.request.urlopen(url) as resp:
            flag = resp.read().decode("utf-8").strip()

    match = re.search(r"academy\{[^}]+\}|picoCTF\{[^}]+\}", flag)
    if match:
        extracted = match.group(0)
    else:
        extracted = flag

    flag_path.write_text(extracted, encoding="utf-8")
    print(f"[+] Flag found: {extracted}", flush=True)
    return extracted

if __name__ == "__main__":
    solve()
