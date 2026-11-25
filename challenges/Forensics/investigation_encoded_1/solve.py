#!/usr/bin/env python3
"""
Solver for investigation_encoded_1 (Forensics / Reverse Engineering)
"""
import os
import struct

def solve():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bin_path = os.path.join(script_dir, "investigation-encoded-1-mystery")
    out_path = os.path.join(script_dir, "investigation-encoded-1-output")

    with open(bin_path, "rb") as f:
        elf_data = f.read()

    with open(out_path, "rb") as f:
        out_bytes = f.read()

    # Locate secret and matrix in .rodata
    # secret begins with: b8 ea 8e ba 3a 88 ae 8e e8 aa 28 bb b8 eb 8b a8
    secret_magic = bytes.fromhex("b8ea8eba3a88ae8ee8aa28bbb8eb8ba8ee3a3bb8bba3bae2e8a8e2b8ab8bb8eae3aee3ba80")
    secret_pos = elf_data.find(secret_magic)
    if secret_pos == -1:
        raise ValueError("Could not find secret in ELF binary")

    secret = secret_magic
    matrix_pos = secret_pos + 0x40

    def get_bit(idx):
        byte_idx = idx // 8
        bit_idx = idx % 8
        return (secret[byte_idx] >> (7 - bit_idx)) & 1

    char_to_bits = {}
    bits_to_char = {}
    for i in range(27):
        count, start = struct.unpack_from("<II", elf_data, matrix_pos + i * 8)
        ch = chr(ord("a") + i) if i < 26 else " "
        bits = "".join(str(get_bit(j)) for j in range(start, start + count))
        char_to_bits[ch] = bits
        bits_to_char[bits] = ch

    # Convert output bytes to bitstream
    out_bits = "".join(f"{b:08b}" for b in out_bytes)

    # Decode bitstream
    decoded = []
    curr = ""
    for bit in out_bits:
        curr += bit
        if curr in bits_to_char:
            decoded.append(bits_to_char[curr])
            curr = ""

    flag_raw = "".join(decoded).strip()

    # Verify encoding of the flag reproduces identical bytes
    buffChar = 0
    remain = 7
    reencoded = bytearray()

    def save(b):
        nonlocal buffChar, remain
        buffChar |= b
        if remain == 0:
            remain = 7
            reencoded.append(buffChar)
            buffChar = 0
        else:
            buffChar = (buffChar << 1) & 0xff
            remain -= 1

    for ch in flag_raw:
        bits = char_to_bits[ch]
        for b in bits:
            save(int(b))

    while remain != 7:
        save(0)

    assert reencoded == out_bytes, "Re-encoded data does not match target output!"

    flag_file = os.path.join(script_dir, "flag.txt")
    with open(flag_file, "w") as f:
        f.write(flag_raw + "\n")

    print(flag_raw, flush=True)
    return flag_raw

if __name__ == "__main__":
    solve()
