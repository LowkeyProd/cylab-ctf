#!/usr/bin/env python3
"""
Solve script for NSA Backdoor (#283)
Category: Cryptography
"""
import sys
from binascii import unhexlify
import gmpy2
from gmpy2 import mpz, gcd, invert

def solve():
    print("[*] Solving NSA Backdoor...", flush=True)
    with open('output.txt', 'r') as f:
        lines = f.readlines()

    n = mpz(lines[0].split('=')[1].strip(), 16)
    c = mpz(lines[1].split('=')[1].strip(), 16)

    print(f"[*] Modulus n bit length: {n.bit_length()}", flush=True)

    # Step 1: Factor n using Pollard's p-1
    print("[*] Factoring n with Pollard's p - 1...", flush=True)
    a = mpz(2)
    prime = 2
    p = None
    while prime < 300000:
        pk = prime
        while pk * prime <= 300000:
            pk *= prime
        a = pow(a, pk, n)
        g = gcd(a - 1, n)
        if 1 < g < n:
            p = g
            break
        elif g == n:
            break
        prime = int(gmpy2.next_prime(prime))

    if p is None:
        raise RuntimeError("Failed to factor n with Pollard's p - 1")

    q = n // p
    print(f"[+] Found factor p ({p.bit_length()} bits) and q ({q.bit_length()} bits)", flush=True)

    # Step 2: Factor p - 1 and q - 1
    def factor_smooth(num, max_p=200000):
        factors = []
        rem = num
        pr = 2
        while pr <= max_p and rem > 1:
            if rem % pr == 0:
                count = 0
                while rem % pr == 0:
                    count += 1
                    rem //= pr
                factors.append((pr, count))
            pr = int(gmpy2.next_prime(pr))
        if rem > 1:
            raise ValueError(f"Number not smooth up to {max_p}: leftover {rem}")
        return factors

    print("[*] Factoring p - 1 and q - 1...", flush=True)
    p_factors = factor_smooth(p - 1)
    q_factors = factor_smooth(q - 1)
    print(f"[+] p - 1 has {len(p_factors)} prime factor powers, max factor: {p_factors[-1][0]}", flush=True)
    print(f"[+] q - 1 has {len(q_factors)} prime factor powers, max factor: {q_factors[-1][0]}", flush=True)

    # Step 3: Pohlig-Hellman discrete logarithm
    def bsgs(g, h, p_mod, order):
        m = int(gmpy2.isqrt(order)) + 1
        table = {}
        cur = mpz(1)
        for j in range(m):
            table[cur] = j
            cur = (cur * g) % p_mod

        step = invert(pow(g, m, p_mod), p_mod)
        gamma = h
        for i in range(m):
            if gamma in table:
                return i * m + table[gamma]
            gamma = (gamma * step) % p_mod
        return None

    def pohlig_hellman_prime_power(g, h, p_mod, q_factor, e):
        x = 0
        gamma = pow(g, q_factor ** (e - 1), p_mod)
        for k in range(e):
            hk = pow((invert(pow(g, x, p_mod), p_mod) * h) % p_mod, q_factor ** (e - 1 - k), p_mod)
            d = bsgs(gamma, hk, p_mod, q_factor)
            if d is None:
                raise ValueError(f"BSGS failed for factor {q_factor}")
            x += d * (q_factor ** k)
        return x

    def pohlig_hellman(g, h, p_mod, factors):
        rem_list = []
        mod_list = []
        for pi, ei in factors:
            mod = pi ** ei
            gi = pow(g, (p_mod - 1) // mod, p_mod)
            hi = pow(h, (p_mod - 1) // mod, p_mod)
            xi = pohlig_hellman_prime_power(gi, hi, p_mod, pi, ei)
            rem_list.append(xi)
            mod_list.append(mod)
        return rem_list, mod_list

    def crt(remainders, moduli):
        M = mpz(1)
        for m in moduli:
            M *= m
        x = mpz(0)
        for r, m in zip(remainders, moduli):
            Mi = M // m
            inv = invert(Mi, m)
            x = (x + r * Mi * inv) % M
        return x, M

    print("[*] Solving DLP modulo p...", flush=True)
    rems_p, mods_p = pohlig_hellman(mpz(3), c % p, p, p_factors)
    x_p, M_p = crt(rems_p, mods_p)

    print("[*] Solving DLP modulo q...", flush=True)
    rems_q, mods_q = pohlig_hellman(mpz(3), c % q, q, q_factors)
    x_q, M_q = crt(rems_q, mods_q)

    # Step 4: Generalized CRT to combine mod p-1 and mod q-1
    g_pq = gcd(M_p, M_q)
    diff = (x_q - x_p) // g_pq
    mod2 = M_q // g_pq
    inv = invert((M_p // g_pq) % mod2, mod2)
    k = (diff * inv) % mod2
    flag_int = x_p + M_p * k

    # Verification
    assert pow(3, flag_int, n) == c, "Decrypted flag does not satisfy pow(3, flag, n) == c"

    hex_str = hex(flag_int)[2:]
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    flag = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')

    print(f"[+] Flag recovered: {flag}", flush=True)

    with open('flag.txt', 'w') as f:
        f.write(flag + '\n')
    print("[+] Flag written to flag.txt", flush=True)

    return flag

if __name__ == "__main__":
    solve()
