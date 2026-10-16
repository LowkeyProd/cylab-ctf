#!/usr/bin/env python3
"""
Solve script for Investigative Reversing 1 (#27)
Category: Forensics / Reverse Engineering

Extracts trailing data appended after PNG IEND markers and reverses
the encoding applied by the binary 'investigative-reversing-1-mystery'.
"""

import os
import sys
from pathlib import Path

PNG_IEND = b"IEND\xae\x42\x60\x82"

def extract_trailing(filepath: Path) -> bytes:
    with open(filepath, "rb") as f:
        data = f.read()
    idx = data.find(PNG_IEND)
    if idx == -1:
        raise ValueError(f"IEND marker not found in {filepath}")
    return data[idx + len(PNG_IEND):]

def solve():
    base_dir = Path(__file__).resolve().parent
    img1_path = base_dir / "investigative-reversing-1-mystery.png"
    img2_path = base_dir / "investigative-reversing-1-mystery2.png"
    img3_path = base_dir / "investigative-reversing-1-mystery3.png"

    m1 = extract_trailing(img1_path)
    m2 = extract_trailing(img2_path)
    m3 = extract_trailing(img3_path)

    buf = [0] * 26

    # Reverse engineering mapping:
    # 1. m2[0] = (buf[0] + 21) & 0xff
    buf[0] = (m2[0] - 21) & 0xff

    # 2. m3[0] = buf[1]
    buf[1] = m3[0]

    # 3. m3[1] = buf[2]
    buf[2] = m3[1]

    # 4. m2[1] = (buf[3] + 4) & 0xff
    buf[3] = (m2[1] - 4) & 0xff

    # 5. m1[0] = buf[4]
    buf[4] = m1[0]

    # 6. m3[2] = buf[5]
    buf[5] = m3[2]

    # 7. m1[1..4] = buf[6..9]
    for idx, i in enumerate(range(6, 10)):
        buf[i] = m1[1 + idx]

    # 8. m3[3..7] = buf[10..14]
    for idx, j in enumerate(range(10, 15)):
        buf[j] = m3[3 + idx]

    # 9. m1[5..15] = buf[15..25]
    for idx, k in enumerate(range(15, 26)):
        buf[k] = m1[5 + idx]

    flag = bytes(buf).decode("latin-1")
    print(flag)

    flag_file = base_dir / "flag.txt"
    with open(flag_file, "w", encoding="utf-8") as f:
        f.write(flag.strip() + "\n")

    return flag

if __name__ == "__main__":
    solve()
