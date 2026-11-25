# Writeup: It's Not My Fault 2

## Header & Metadata
- **Challenge:** It's Not My Fault 2 (ID: 120)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `nc xebec.cylabacademy.net 21159`
- **Attached Files:** not_my_fault_again.py
- **Official Flag:** `academy{p0lyn0m14l_4r17hm371c_73chn1qu35_4r3_u53ful_1n_m4ny_f13ld5!!!}`

---

## Mô tả bài toán (Overview / Analysis)
What do you mean RSA with CRT has an attack that's not a fault attack?
Connect with `nc xebec.cylabacademy.net 21159`. <a href='https://challenge-files.cylabacademy.net/library/e5d0c66d8747e1173fb8a85ec6c11653cb8df050ff73f29c1df444c506295d99/not_my_fault_again.py' download>not_my_fault_again.py</a>

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
import socket
import re
import time
import hashlib
from pathlib import Path
import flint
import gmpy2

def solve_pow(vals1, vals2):
    print(f"[*] Solving PoW for prefix='{vals1}', target_suffix='{vals2}'...", flush=True)
    t0 = time.time()
    p = vals1.encode()
    i = 0
    while True:
        cand = p + b"%d" % i
        if hashlib.md5(cand).hexdigest().endswith(vals2):
            res = (p + b"%d" % i).decode()
            print(f"[+] PoW solved: '{res}' in {time.time()-t0:.2f}s (steps={i})", flush=True)
            return res
        i += 1

def get_target():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 34400
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("HOST=") and line.split("=", 1)[1]:
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

class SocketReader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def readline(self):
        while b"\n" not in self.buf:
            data = self.sock.recv(4096)
            if not data:
                break
            self.buf += data
        if b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            return line.decode(errors="ignore")
        line = self.buf.decode(errors="ignore")
        self.buf = b""
        return line

    def read_until(self, substring):
        sub = substring.encode()
        while sub not in self.buf:
            data = self.sock.recv(4096)
            if not data:
                break
            self.buf += data
        idx = self.buf.find(sub)
        if idx != -1:
            res = self.buf[:idx + len(sub)]
            self.buf = self.buf[idx + len(sub):]
            return res.decode(errors="ignore")
        res = self.buf
        self.buf = b""
        return res.decode(errors="ignore")

def poly_from_roots(roots, ctx):
    polys = [ctx([-r, 1]) for r in roots]
    while len(polys) > 1:
        new_polys = []
        for i in range(0, len(polys), 2):
            if i + 1 < len(polys):
                new_polys.append(polys[i] * polys[i + 1])
            else:
                new_polys.append(polys[i])
        polys = new_polys
    return polys[0]

def solve_rsa_pinch(n, e, bits=36):
    print(f"[*] Starting Pinch's attack for CRT RSA (BITS={bits})...", flush=True)
    t0 = time.time()
    m = 3
    B0 = 1 << 19  # 524288
    num_roots = B0 // 2  # 262144 odd roots
    total_d1 = ( (1 << bits) + B0 - 1 ) // B0 + 1  # 131073 giant steps

    ctx = flint.fmpz_mod_poly_ctx(n)

    print(f"[*] Precomputing {num_roots} baby steps (odd roots)...", flush=True)
    inv_m_e = pow(pow(m, e, n), -1, n)
    v = inv_m_e
    v2 = (v * v) % n
    cur = (m * v) % n  # for d0 = 1: m * v^1

    roots = []
    for _ in range(num_roots):
        roots.append(cur)
        cur = (cur * v2) % n

    print(f"[*] Constructing polynomial from {num_roots} roots...", flush=True)
    t_poly = time.time()
    F = poly_from_roots(roots, ctx)
    print(f"[+] Polynomial constructed in {time.time()-t_poly:.2f}s, degree={F.degree()}", flush=True)

    print(f"[*] Evaluating {total_d1} giant step points in chunks...", flush=True)
    u = pow(m, e * B0, n)

    CHUNK_SIZE = 32768
    cur_u = 1
    found_p = None

    total_chunks = (total_d1 + CHUNK_SIZE - 1) // CHUNK_SIZE
    chunk_idx = 0
    d1_base = 0

    while d1_base < total_d1:
        chunk_pts = []
        chunk_len = min(CHUNK_SIZE, total_d1 - d1_base)
        for _ in range(chunk_len):
            chunk_pts.append(cur_u)
            cur_u = (cur_u * u) % n

        chunk_idx += 1
        t_eval = time.time()
        evals = F.multipoint_evaluate(chunk_pts)
        eval_time = time.time() - t_eval
        print(f"    Chunk {chunk_idx}/{total_chunks} (d1={d1_base}..{d1_base+chunk_len-1}) evaluated in {eval_time:.2f}s", flush=True)

        for offset, val in enumerate(evals):
            val_int = int(val)
            if val_int % n == 0:
                continue
            g = gmpy2.gcd(val_int, n)
            if 1 < g < n:
                found_p = int(g)
                d1_found = d1_base + offset
                print(f"[+] Found prime factor p at d1={d1_found} in {time.time()-t0:.2f}s!", flush=True)
                break

        if found_p is not None:
            break

        d1_base += chunk_len

    if found_p is None:
        raise ValueError("[-] Factor not found within range!")

    p = found_p
    q = n // p
    assert p * q == n, "p * q != n!"
    print(f"[+] Successfully factored n!", flush=True)
    print(f"    p = {p}", flush=True)
    print(f"    q = {q}", flush=True)
    return p, q

def main():
    host, port = get_target()
    print(f"[*] Connecting to {host}:{port}...", flush=True)
    sock = socket.create_connection((host, port), timeout=300)
    sock.settimeout(300)

    reader = SocketReader(sock)

    # Read banner and PoW prompt until "hex digits:" is in buffer
    prompt_raw = reader.read_until("hex digits:")
    rest_of_line = reader.readline()
    prompt = prompt_raw + rest_of_line
    print(f"[<] {prompt.strip()}", flush=True)

    match = re.search(r'starts with "(\d+)" .* hex digits: ([0-9a-fA-F]+)', prompt)
    if not match:
        raise ValueError(f"Could not parse PoW prompt: {prompt}")

    vals1, vals2 = match.group(1), match.group(2)
    pow_solution = solve_pow(vals1, vals2)
    print(f"[>] Sending PoW: {pow_solution}", flush=True)
    sock.sendall((pow_solution + "\n").encode())

    # Receive public modulus n and clue e
    n = None
    e = None
    while n is None or e is None:
        line = reader.readline().strip()
        print(f"[<] {line}", flush=True)
        if line.startswith("Public Modulus :"):
            n = int(line.split(":", 1)[1].strip())
        elif line.startswith("Clue :"):
            e = int(line.split(":", 1)[1].strip())

    print(f"[+] Modulus n = {n}", flush=True)
    print(f"[+] Clue e    = {e}", flush=True)

    # Factor n using Pinch's attack
    p, q = solve_rsa_pinch(n, e, bits=36)
    ans = p + q
    print(f"[+] p + q = {ans}", flush=True)
    print(f"[>] Sending ans: {ans}", flush=True)
    sock.sendall((str(ans) + "\n").encode())

    # Read response for flag
    flag = None
    while True:
        line = reader.readline()
        if not line:
            break
        line = line.strip()
        print(f"[<] {line}", flush=True)
        flag_match = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', line)
        if flag_match:
            cand = flag_match.group(1)
            # Decoy checks
            if not any(d in cand.lower() for d in ['fake', 'decoy', 'honey', 'not_the_flag', 'dummy']):
                flag = cand

    sock.close()

    if flag:
        print(f"\n[+] FLAG FOUND: {flag}", flush=True)
        flag_path = Path(__file__).resolve().parent / "flag.txt"
        flag_path.write_text(flag)
        print(f"[+] Saved flag to {flag_path}", flush=True)
    else:
        print("[-] Flag not found in server response!", flush=True)

if __name__ == "__main__":
    main()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{p0lyn0m14l_4r17hm371c_73chn1qu35_4r3_u53ful_1n_m4ny_f13ld5!!!}
```
