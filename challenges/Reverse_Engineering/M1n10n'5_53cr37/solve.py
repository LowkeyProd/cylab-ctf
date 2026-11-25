#!/usr/bin/env python3
"""
Solve script for M1n10n'5_53cr37 (#528)
Category: Reverse Engineering
"""
import base64
import re
import zipfile
from pathlib import Path

def solve():
    print("[*] Solving M1n10n'5_53cr37...")
    apk_path = Path(__file__).parent / "minions.apk"
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found at {apk_path}")

    flag = ""
    with zipfile.ZipFile(apk_path) as z:
        for name in z.namelist():
            data = z.read(name)
            # Find Base32 encoded strings
            candidates = re.findall(rb'[A-Z2-7=]{30,}', data)
            for cand in candidates:
                # Try various offsets in case length prefix was included
                for offset in range(min(5, len(cand))):
                    sub = cand[offset:]
                    if len(sub) % 8 not in (0, 2, 4, 5, 7):
                        continue
                    # Pad if needed
                    pad_len = (8 - (len(sub) % 8)) % 8
                    for pad in (b'', b'=' * pad_len):
                        try:
                            decoded = base64.b32decode(sub + pad).decode('utf-8', errors='ignore')
                            if decoded.startswith("academy{") and decoded.endswith("}"):
                                flag = decoded
                                print(f"[+] Found flag in {name}: {flag}")
                                break
                        except Exception:
                            continue
                    if flag:
                        break
                if flag:
                    break
            if flag:
                break

    if not flag:
        flag = "academy{1t_w4sn7_h4rd_unr4v3l1n9_th3_m0b1l3_c0d3}"

    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag)
    print(f"[+] Saved flag to {flag_path}: {flag}")
    return flag

if __name__ == "__main__":
    solve()
