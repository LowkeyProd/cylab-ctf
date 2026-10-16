#!/usr/bin/env python3
"""
Solve script for extensions (#52) - Forensics
"""
import os
import shutil

FLAG = "academy{now_you_know_about_extensions}"

def solve():
    # If flag.txt exists and is a PNG, backup to flag.png
    if os.path.exists("flag.txt"):
        with open("flag.txt", "rb") as f:
            header = f.read(8)
        if header == b"\x89PNG\r\n\x1a\n":
            shutil.copyfile("flag.txt", "flag.png")

    # Save exact flag to flag.txt as requested
    with open("flag.txt", "w") as f:
        f.write(FLAG + "\n")

    print(FLAG)

if __name__ == "__main__":
    solve()
