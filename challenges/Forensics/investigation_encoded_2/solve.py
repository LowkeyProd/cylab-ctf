#!/usr/bin/env python3
"""
Solver for investigation_encoded_2 (Forensics / Reverse Engineering)
"""
import os
import struct

def solve():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    bin_path = os.path.join(script_dir, "no_auth_mistery")
    out_path = os.path.join(script_dir, "investigation-encoded-2-output")

    with open(bin_path, "rb") as f:
        elf_data = f.read()

    # Extract secret and indexTable from ELF .rodata section
    # Based on symbols: secret at 0x1300 (size 71 bytes), indexTable at 0x1360 (size 38 uint32_t)
    secret = elf_data[0x1300:0x1300 + 71]
    table = struct.unpack("<38I", elf_data[0x1360:0x1360 + 38 * 4])

    secret_bits = "".join(f"{b:08b}" for b in secret)

    # Build mapping from bit representation back to original character
    bits_to_char = {}
    for ch in "abcdefghijklmnopqrstuvwxyz0123456789 ":
        if ch == " ":
            v = 36
        elif "0" <= ch <= "9":
            v = ord(ch) - ord("0") + 26
        else:
            v = ord(ch) - ord("a")

        enc_v = (v + 18) % 36 if v != 36 else 36
        code = secret_bits[table[enc_v]:table[enc_v + 1]]
        bits_to_char[code] = ch

    # Read the encoded output file
    with open(out_path, "rb") as f:
        out_bytes = f.read()

    out_bits = "".join(f"{b:08b}" for b in out_bytes)

    # Decode bitstream
    decoded = []
    cur = ""
    for bit in out_bits:
        cur += bit
        if cur in bits_to_char:
            decoded.append(bits_to_char[cur])
            cur = ""

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
        c = ord(ch.lower())
        if c == 0x20:
            c = 0x85
        elif 0x2f < c <= 0x39:
            c += 0x4b
        c -= 0x61
        if c != 0x24:
            c = (c + 18) % 36

        start_idx = table[c]
        end_idx = table[c + 1]
        for i in range(start_idx, end_idx):
            byte_idx = i // 8
            bit_idx = i % 8
            bit = (secret[byte_idx] >> (7 - bit_idx)) & 1
            save(bit)

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
