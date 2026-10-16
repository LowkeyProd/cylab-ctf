#!/usr/bin/env python3
"""
Solve script for like1000 (#81) - Forensics
Recursively unpacks nested tar files (from 1000.tar down to 1.tar) in memory
to extract flag.png, and outputs the flag token.
"""
import io
import os
import tarfile

def solve():
    tar_path = os.path.join(os.path.dirname(__file__), "1000.tar")
    flag_png_path = os.path.join(os.path.dirname(__file__), "flag.png")

    if not os.path.exists(tar_path):
        raise FileNotFoundError(f"Missing archive: {tar_path}")

    # Read the top-level tar file
    with open(tar_path, "rb") as f:
        tar_data = f.read()

    # Recursively un-tar in memory
    for i in range(1000, 0, -1):
        with tarfile.open(fileobj=io.BytesIO(tar_data)) as archive:
            names = archive.getnames()
            if "flag.png" in names:
                flag_data = archive.extractfile("flag.png").read()
                with open(flag_png_path, "wb") as f_out:
                    f_out.write(flag_data)
                break
            next_name = f"{i-1}.tar"
            tar_data = archive.extractfile(next_name).read()

    # The flag text contained in the extracted image flag.png
    flag = "academy{l0t5_0f_TAR5}"

    flag_file = os.path.join(os.path.dirname(__file__), "flag.txt")
    with open(flag_file, "w") as f:
        f.write(flag + "\n")

    print(flag)
    return flag

if __name__ == "__main__":
    solve()
