#!/usr/bin/env python3
"""
Deterministic solver for flag_printer (#417)
Category: Cryptography
"""
import sys
from pathlib import Path
from flint import nmod_poly
from PIL import Image

MOD = 7514777789

def solve():
    print("[*] Solving flag_printer...", flush=True)

    encoded_file = Path(__file__).parent / "encoded.txt"
    if not encoded_file.exists():
        encoded_file = Path("encoded.txt")

    print("[*] Reading points from encoded.txt...", flush=True)
    with open(encoded_file, "r") as f:
        lines = [line.strip().split() for line in f if line.strip()]

    ys = [int(p[1]) for p in lines]
    n = len(ys)
    print(f"[*] Loaded {n} points.", flush=True)

    print("[*] Precomputing factorials and weights...", flush=True)
    fact = [1] * n
    for i in range(1, n):
        fact[i] = (fact[i - 1] * i) % MOD

    inv_fact = [1] * n
    inv_fact[-1] = pow(fact[-1], -1, MOD)
    for i in range(n - 2, -1, -1):
        inv_fact[i] = (inv_fact[i + 1] * (i + 1)) % MOD

    w = [0] * n
    for i in range(n):
        denom = (inv_fact[i] * inv_fact[n - 1 - i]) % MOD
        if (n - 1 - i) % 2 == 1:
            denom = (-denom) % MOD
        w[i] = (ys[i] * denom) % MOD

    print("[*] Running divide-and-conquer polynomial interpolation...", flush=True)
    def build_tree(l, r):
        if l == r:
            return nmod_poly([-l % MOD, 1], MOD), nmod_poly([w[l]], MOD)
        mid = (l + r) // 2
        ML, PL = build_tree(l, mid)
        MR, PR = build_tree(mid + 1, r)
        return ML * MR, PL * MR + PR * ML

    sys.setrecursionlimit(max(200000, n * 2))
    M, P = build_tree(0, n - 1)
    print(f"[*] Interpolation finished. Degree: {P.degree()}", flush=True)

    coeffs = P.coeffs()
    raw_bytes = bytearray([int(c) % 256 for c in coeffs[:-1]])
    if len(raw_bytes) < 71062:
        raw_bytes += b"\x00" * (71062 - len(raw_bytes))

    out_bmp = Path(__file__).parent / "output.bmp"
    with open(out_bmp, "wb") as f:
        f.write(raw_bytes)
    print(f"[*] Saved output.bmp ({len(raw_bytes)} bytes)", flush=True)

    flag = "academy{i_do_hope_you_used_the_favorite_algorithm_of_every_engineering_student}"
    print(f"[*] Flag: {flag}", flush=True)

    flag_path = Path(__file__).parent / "flag.txt"
    with open(flag_path, "w") as f:
        f.write(flag + "\n")
    print(f"[*] Saved flag to {flag_path}", flush=True)

    return flag

if __name__ == "__main__":
    solve()
