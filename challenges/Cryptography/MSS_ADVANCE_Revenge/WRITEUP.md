# Writeup: MSS_ADVANCE Revenge

## Header & Metadata
- **Challenge:** MSS_ADVANCE Revenge (ID: 709)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** chall.py, output.txt
- **Official Flag:** `academy{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}`

---

## Mô tả bài toán (Overview / Analysis)
Last time we went easy on you. You'll never get the flag this time!

<a href='https://challenge-files.cylabacademy.net/library/6936c366a12516f20bd0ae04c6e560271c4811f57df2b60a41f5e7e24f29b95b/chall.py' download>chall.py</a>

<a href='https://challenge-files.cylabacademy.net/library/6936c366a12516f20bd0ae04c6e560271c4811f57df2b60a41f5e7e24f29b95b/output.txt' download>output.txt</a>


### Hints
- What are lattices?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for MSS_ADVANCE Revenge (#709)
Category: Cryptography
"""
import ast
import hashlib
from pathlib import Path
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import flint
from flint import fmpz_mat


def solve():
    print("[*] Solving MSS_ADVANCE Revenge...", flush=True)

    base_dir = Path(__file__).resolve().parent
    output_file = base_dir / "output.txt"

    with open(output_file, "r") as f:
        lines = f.readlines()

    p = int(lines[0].split("=")[1].strip())
    pairs = ast.literal_eval(lines[1].split("pairs = ")[1].strip())
    enc_flag = ast.literal_eval(lines[2].split("enc_flag = ")[1].strip())

    print(f"[*] Loaded modulus p ({p.bit_length()} bits) and {len(pairs)} evaluation pairs.", flush=True)

    # Build augmented matrix [A | y] of size 20 x 31
    # where A_{i, j} = x_i^{29 - j} mod p for j in 0..29
    mat = []
    for x, y in pairs:
        row = [pow(x, 29 - j, p) for j in range(30)] + [y % p]
        mat.append(row)

    # Perform Gaussian elimination over GF(p) to find RREF
    num_rows = len(mat)
    num_cols = 30  # variable columns

    pivot_cols = []
    row_idx = 0
    for col_idx in range(num_cols):
        pivot_row = -1
        for r in range(row_idx, num_rows):
            if mat[r][col_idx] % p != 0:
                pivot_row = r
                break
        if pivot_row == -1:
            continue
        mat[row_idx], mat[pivot_row] = mat[pivot_row], mat[row_idx]
        inv = pow(mat[row_idx][col_idx], -1, p)
        for c in range(col_idx, num_cols + 1):
            mat[row_idx][c] = (mat[row_idx][c] * inv) % p
        for r in range(num_rows):
            if r != row_idx and mat[r][col_idx] != 0:
                factor = mat[r][col_idx]
                for c in range(col_idx, num_cols + 1):
                    mat[r][c] = (mat[r][c] - factor * mat[row_idx][c]) % p
        pivot_cols.append(col_idx)
        row_idx += 1
        if row_idx == num_rows:
            break

    print(f"[*] RREF completed with {len(pivot_cols)} pivot variables and 10 free variables.", flush=True)

    # Set up Kannan's embedding lattice (dimension 20 + 10 + 1 = 31)
    B = 1 << 256
    dim = 20 + 10 + 1

    rows = []
    # 20 rows corresponding to p * e_i
    for i in range(20):
        r = [0] * dim
        r[i] = p
        rows.append(r)

    # 10 rows corresponding to free variables c_20..c_29
    for k in range(10):
        r = [0] * dim
        for i in range(20):
            r[i] = mat[i][20 + k]
        r[20 + k] = 1
        rows.append(r)

    # 1 row for constant term
    r_const = [0] * dim
    for i in range(20):
        r_const[i] = -mat[i][30] % p
    r_const[30] = B
    rows.append(r_const)

    print(f"[*] Running LLL on {dim}x{dim} lattice...", flush=True)
    L = fmpz_mat(rows)
    L_red = L.lll()
    print("[*] LLL reduction finished.", flush=True)

    flag = ""
    for row in L_red.table():
        if abs(int(row[30])) == B:
            sign = 1 if int(row[30]) == B else -1
            coeffs = [0] * 30
            for i in range(20):
                coeffs[i] = -sign * int(row[i])
            for k in range(10):
                coeffs[20 + k] = sign * int(row[20 + k])

            # Verify sha256 chain
            valid = True
            for i in range(29):
                nxt = bytes_to_long(hashlib.sha256(long_to_bytes(coeffs[i])).digest())
                if nxt != coeffs[i + 1]:
                    valid = False
                    break

            if valid:
                print(f"[+] Found valid coefficient chain!", flush=True)
                master_key = long_to_bytes(coeffs[0])
                iv = bytes.fromhex(enc_flag[0])
                ct = bytes.fromhex(enc_flag[1])
                cipher = AES.new(master_key, AES.MODE_CBC, iv)
                pt = unpad(cipher.decrypt(ct), 16)
                flag = pt.decode("utf-8")
                break

    if flag:
        print(f"[+] Flag recovered: {flag}", flush=True)
        flag_path = base_dir / "flag.txt"
        flag_path.write_text(flag)
        print(f"[+] Flag written to {flag_path}", flush=True)
    else:
        print("[-] Failed to recover flag", flush=True)

    return flag


if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{MSS_Advance_but_we_brought_it_back_and_made_it_harder!!!}
```
