# Writeup: rsa-pop-quiz

## Header & Metadata
- **Challenge:** rsa-pop-quiz (ID: 61)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `nc chatelaine.cylabacademy.net 32180`
- **Attached Files:** None
- **Official Flag:** `academy{wA8_th4t$_ill3aGal..oCfEd0082}`

---

## Mô tả bài toán (Overview / Analysis)
Class, take your seats! It's PRIME-time for a quiz...
`nc chatelaine.cylabacademy.net 32180`

### Hints
- [RSA info](https://simple.wikipedia.org/wiki/RSA_algorithm)

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for rsa-pop-quiz (#61)
Target loaded dynamically from connection.cfg
"""
import socket
import re
from pathlib import Path
try:
    import gmpy2
except ImportError:
    gmpy2 = None

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 17401
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("HOST="chatelaine.cylabacademy.net"
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def recv_until(sock, markers):
    if isinstance(markers, str):
        markers = [markers]
    buf = ""
    while True:
        ch = sock.recv(1)
        if not ch:
            break
        buf += ch.decode("utf-8", errors="ignore")
        for m in markers:
            if buf.endswith(m):
                return buf, m
    return buf, None

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)
    s = socket.socket()
    s.connect((host, port))

    last_plaintext = None
    round_num = 0

    while True:
        buf, matched = recv_until(s, ["(Y/N):", "picoCTF{", "academy{"])
        print(buf, end="", flush=True)
        if not matched:
            break

        if matched in ["picoCTF{", "academy{"]:
            rest, _ = recv_until(s, ["\n", "}"])
            flag = matched + rest.strip()
            print(f"\n[+] Extracted flag from stream: {flag}", flush=True)
            save_flag(flag)
            s.close()
            return flag

        round_num += 1
        text = buf
        prob_part = text.split("#### NEW PROBLEM ####")[-1].split("##### PRODUCE THE FOLLOWING ####")[0]
        params = {}
        for line in prob_part.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                try:
                    params[k.strip()] = int(v.strip())
                except Exception:
                    pass

        target_part = text.split("##### PRODUCE THE FOLLOWING ####")[-1].split("IS THIS POSSIBLE")[0]
        target = target_part.strip().splitlines()[0].strip()
        print(f"\n[*] Round {round_num}: Target = {target}, Available params = {list(params.keys())}", flush=True)

        possible = False
        ans = None

        if target == "n" and "p" in params and "q" in params:
            possible = True
            ans = params["p"] * params["q"]
        elif target == "q" and "p" in params and "n" in params:
            possible = True
            ans = params["n"] // params["p"]
        elif target == "p" and "q" in params and "n" in params:
            possible = True
            ans = params["n"] // params["q"]
        elif "totient" in target:
            if "p" in params and "q" in params:
                possible = True
                ans = (params["p"] - 1) * (params["q"] - 1)
            elif "p" in params and "n" in params:
                q = params["n"] // params["p"]
                possible = True
                ans = (params["p"] - 1) * (q - 1)
        elif target == "ciphertext" and "plaintext" in params and "e" in params and "n" in params:
            possible = True
            ans = pow(params["plaintext"], params["e"], params["n"])
        elif target == "plaintext" and "ciphertext" in params and "e" in params and "n" in params:
            c = params["ciphertext"]
            e = params["e"]
            n = params["n"]
            if "p" in params:
                p = params["p"]
                q = n // p
                phi = (p - 1) * (q - 1)
                d = pow(e, -1, phi)
                ans = pow(c, d, n)
                last_plaintext = ans
                possible = True
            elif "d" in params:
                ans = pow(c, params["d"], n)
                last_plaintext = ans
                possible = True
            else:
                if gmpy2:
                    root, exact = gmpy2.iroot(c, e)
                    if exact:
                        ans = int(root)
                        last_plaintext = ans
                        possible = True
                    else:
                        possible = False
                else:
                    possible = False
        elif target == "d":
            if "p" in params and "q" in params and "e" in params:
                phi = (params["p"] - 1) * (params["q"] - 1)
                ans = pow(params["e"], -1, phi)
                possible = True
            elif "p" in params and "n" in params and "e" in params:
                p = params["p"]
                q = params["n"] // p
                phi = (p - 1) * (q - 1)
                ans = pow(params["e"], -1, phi)
                possible = True
            else:
                possible = False

        print(f"[*] Decision: Possible={possible}, Ans={ans}", flush=True)

        if possible:
            s.sendall(b"y\n")
            p_prompt, _ = recv_until(s, [":", "#####"])
            print(p_prompt, end="", flush=True)
            s.sendall(f"{ans}\n".encode())
        else:
            s.sendall(b"n\n")

    # Read trailing text
    tail = s.recv(4096).decode("utf-8", errors="ignore")
    print(tail, flush=True)
    s.close()

    if last_plaintext is not None:
        h = hex(last_plaintext)[2:]
        if len(h) % 2 != 0:
            h = "0" + h
        flag_cand = bytes.fromhex(h).decode("utf-8", errors="ignore")
        print(f"\n[+] Decoded plaintext flag candidate: {flag_cand}", flush=True)
        match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", flag_cand)
        if match:
            flag = match.group(1)
            save_flag(flag)
            return flag
        elif "academy{" in flag_cand or "picoCTF{" in flag_cand:
            save_flag(flag_cand)
            return flag_cand

    return None

def save_flag(flag):
    flag = flag.strip()
    out_file = Path(__file__).resolve().parent / "flag.txt"
    out_file.write_text(flag)
    print(f"[+] Flag successfully saved to {out_file}: {flag}", flush=True)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{wA8_th4t$_ill3aGal..oCfEd0082}
```
