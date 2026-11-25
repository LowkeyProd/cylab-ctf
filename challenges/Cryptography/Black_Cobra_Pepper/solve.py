#!/usr/bin/env python3
"""
Solve script for Black Cobra Pepper (#701)
Category: Cryptography

Vulnerability:
In chall.py, the AES implementation has no non-linear components:
- `sub_bytes(state)` is a no-op (identity function).
- `sub_word(word)` is a no-op.
- `rcon(word)` is a no-op.
All remaining operations (ShiftRows, MixColumns, AddRoundKey) are linear over GF(2).
Consequently, AES(P, K) = L(P) ^ C(K), where L is a linear transformation over GF(2)
independent of the key, and C(K) depends only on the key.
Given C1 = AES(pt1, key) and C2 = AES(flag, key):
C1 ^ C2 = L(pt1 ^ flag).
By representing L as a 128x128 matrix over GF(2), we can invert it to recover
(pt1 ^ flag), and thus flag = pt1 ^ L^{-1}(C1 ^ C2).
"""
import sys
from pathlib import Path

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def split(full_key):
    k = full_key
    sub_keys = ["", "", "", ""]
    for i in range(len(k)):
        sub_keys[i % 4] = str(sub_keys[i % 4]) + str(k[0])
        k = k[1:]
    return sub_keys

def glue(parts):
    k = ""
    for i in range(32):
        k = str(k) + str(parts[i % 4][0])
        parts[i % 4] = str(parts[i % 4][1:])
    return k

def rot_word(word):
    return str(word[2:]) + str(word[0:2])

def sub_word(word):
    return word

def rcon(word):
    return word

def gen_keys(master_key):
    keys = []
    rounds = 0
    k = master_key
    while rounds < 11:
        keys.append(k)
        sub_keys = split(k)
        sub_keys[-1] = rot_word(sub_keys[-1])
        sub_keys[-1] = sub_word(sub_keys[-1])
        sub_keys[-1] = rcon(sub_keys[-1])
        sub_keys[0] = xor(bytes.fromhex(sub_keys[0]), bytes.fromhex(sub_keys[-1])).hex()
        sub_keys[1] = xor(bytes.fromhex(sub_keys[1]), bytes.fromhex(sub_keys[0])).hex()
        sub_keys[2] = xor(bytes.fromhex(sub_keys[2]), bytes.fromhex(sub_keys[1])).hex()
        sub_keys[3] = xor(bytes.fromhex(sub_keys[3]), bytes.fromhex(sub_keys[2])).hex()
        k = glue(sub_keys)
        rounds += 1
    return keys

def to_matrix(key):
    bytes_list = [int(key[i:i + 2], 16) for i in range(0, 32, 2)]
    array = [[0] * 4 for _ in range(4)]
    for i in range(16):
        row = i % 4
        col = i // 4
        array[row][col] = hex(bytes_list[i])[2:]
    return array

def from_matrix(matrix):
    reconstructed = ""
    for col in range(4):
        for row in range(4):
            reconstructed += matrix[row][col].zfill(2)
    return reconstructed

def sub_bytes(state):
    return state

def shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = (
        state[1][1],
        state[1][2],
        state[1][3],
        state[1][0],
    )
    state[2][0], state[2][1], state[2][2], state[2][3] = (
        state[2][2],
        state[2][3],
        state[2][0],
        state[2][1],
    )
    state[3][0], state[3][1], state[3][2], state[3][3] = (
        state[3][3],
        state[3][0],
        state[3][1],
        state[3][2],
    )
    return state

def gmul(a, b):
    b = int(b, 16)
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return p

def mix_columns(s):
    ss = [[0] * 4 for _ in range(4)]
    for c in range(4):
        ss[0][c] = hex(
            gmul(0x02, s[0][c])
            ^ gmul(0x03, s[1][c])
            ^ int(s[2][c], 16)
            ^ int(s[3][c], 16)
        )[2:].zfill(2)
        ss[1][c] = hex(
            int(s[0][c], 16)
            ^ gmul(0x02, s[1][c])
            ^ gmul(0x03, s[2][c])
            ^ int(s[3][c], 16)
        )[2:].zfill(2)
        ss[2][c] = hex(
            int(s[0][c], 16)
            ^ int(s[1][c], 16)
            ^ gmul(0x02, s[2][c])
            ^ gmul(0x03, s[3][c])
        )[2:].zfill(2)
        ss[3][c] = hex(
            gmul(0x03, s[0][c])
            ^ int(s[1][c], 16)
            ^ int(s[2][c], 16)
            ^ gmul(0x02, s[3][c])
        )[2:].zfill(2)
    for i in range(4):
        for j in range(4):
            s[i][j] = ss[i][j]
    return s

def AES(plaintext, key):
    ciphertext = plaintext
    round_keys = gen_keys(key)
    ciphertext = xor(bytes.fromhex(round_keys[0]), bytes.fromhex(ciphertext)).hex()
    for i in range(1, 10):
        ciphertext = to_matrix(ciphertext)
        sub_bytes(ciphertext)
        shift_rows(ciphertext)
        mix_columns(ciphertext)
        ciphertext = from_matrix(ciphertext)
        ciphertext = xor(bytes.fromhex(round_keys[i]), bytes.fromhex(ciphertext)).hex()
    ciphertext = to_matrix(ciphertext)
    sub_bytes(ciphertext)
    shift_rows(ciphertext)
    ciphertext = from_matrix(ciphertext)
    ciphertext = xor(bytes.fromhex(round_keys[10]), bytes.fromhex(ciphertext)).hex()
    return ciphertext

def L(hex_pt):
    return AES(hex_pt, "00" * 16)

def solve():
    print("[*] Solving Black Cobra Pepper...")
    output_path = Path(__file__).parent / "output.txt"
    with open(output_path, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    c1 = lines[0]
    c2 = lines[1]
    pt1 = "72616e646f6d64617461313131313131"

    z_bytes = xor(bytes.fromhex(c1), bytes.fromhex(c2))
    z_int = int.from_bytes(z_bytes, "big")

    # Evaluate L on each basis vector of GF(2)^128
    col_values = []
    for i in range(128):
        ei = 1 << (127 - i)
        ei_hex = ei.to_bytes(16, "big").hex()
        out_hex = L(ei_hex)
        col_values.append(int.from_bytes(bytes.fromhex(out_hex), "big"))

    # Set up system of linear equations A * x = z over GF(2)
    A = []
    for j in range(128):
        row = [(col_values[i] >> (127 - j)) & 1 for i in range(128)]
        row.append((z_int >> (127 - j)) & 1)
        A.append(row)

    # Gaussian elimination over GF(2)
    for col in range(128):
        pivot = None
        for r in range(col, 128):
            if A[r][col] == 1:
                pivot = r
                break
        assert pivot is not None, f"Matrix is singular at col {col}"
        A[col], A[pivot] = A[pivot], A[col]
        for r in range(128):
            if r != col and A[r][col] == 1:
                for c in range(col, 129):
                    A[r][c] ^= A[col][c]

    # Solution vector
    x_int = 0
    for r in range(128):
        x_int = (x_int << 1) | A[r][128]

    x_bytes = x_int.to_bytes(16, "big")
    flag_bytes = xor(bytes.fromhex(pt1), x_bytes)
    flag = flag_bytes.decode("utf-8", errors="replace")

    print(f"[+] Flag found: {flag}")
    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag)
    print(f"[+] Flag written to {flag_path}")
    return flag

if __name__ == "__main__":
    solve()
