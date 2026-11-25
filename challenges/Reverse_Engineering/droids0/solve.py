#!/usr/bin/env python3
"""
Solve script for droids0 (#11)
Reverse Engineering of zero.apk / libhellojni.so
"""
import os
import re
import zipfile

def solve():
    # Attempt to read libhellojni from zero.apk or local directory
    elf_data = None
    if os.path.exists("zero.apk"):
        with zipfile.ZipFile("zero.apk", "r") as z:
            for arch in ["lib/x86_64/libhellojni.so", "lib/arm64-v8a/libhellojni.so", "lib/x86/libhellojni.so"]:
                if arch in z.namelist():
                    elf_data = z.read(arch)
                    break
    if elf_data is None and os.path.exists("libhellojni_x64.so"):
        with open("libhellojni_x64.so", "rb") as f:
            elf_data = f.read()

    if not elf_data:
        raise FileNotFoundError("Could not find zero.apk or libhellojni shared library.")

    # In marjoram(), the key is "notexist" and unscramble() XORs the ciphertext with key
    # In lib/x86_64/libhellojni.so:
    # 0x1a04: "notexist\0againmissing\0"
    # followed by the 35-byte scrambled flag
    key = b"notexist"
    marker = b"notexist\x00againmissing\x00"
    idx = elf_data.find(marker)
    if idx == -1:
        raise ValueError("Marker not found in binary.")

    scrambled = elf_data[idx + len(marker) : idx + len(marker) + 35]
    flag_bytes = bytes([b ^ key[i % len(key)] for i, b in enumerate(scrambled)])
    flag = flag_bytes.decode("utf-8", errors="ignore")

    print(f"Decrypted flag: {flag}")

    match = re.search(r"(?:academy|picoCTF)\{[^}]+\}", flag)
    if match:
        final_flag = match.group(0)
        with open("flag.txt", "w") as f:
            f.write(final_flag.strip() + "\n")
        print(f"Successfully extracted and saved flag: {final_flag}")
        return final_flag
    else:
        raise ValueError(f"Flag pattern not found in decrypted text: {flag}")

if __name__ == "__main__":
    solve()
