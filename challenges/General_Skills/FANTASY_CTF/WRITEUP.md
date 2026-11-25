# Writeup: FANTASY CTF

## Header & Metadata
- **Challenge:** FANTASY CTF (ID: 471)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `nc chatelaine.cylabacademy.net 26424`
- **Attached Files:** None
- **Official Flag:** `academy{m1113n1um_3d1710n_2ad04d2b}`

---

## Mô tả bài toán (Overview / Analysis)
Play this short game to get familiar with terminal applications and some of the
most important rules in scope for picoCTF.
Connect to the program with netcat:

`$ nc chatelaine.cylabacademy.net 26424`

### Hints
- When a choice is presented like [a/b/c], choose one, for example: `c` and then
  press Enter.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Deterministic solver for FANTASY computer science competition (ID: 471)
"""
import sys
import socket
import re
from pathlib import Path

# Ensure UTF-8 output and unbuffered printing
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 26424
    if cfg_file.exists():
        for line in cfg_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("HOST=") and line.split("=", 1)[1]:
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port


def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)

    s = socket.create_connection((host, port), timeout=15)
    s.settimeout(2.5)

    answers = ["c", "a"]
    ans_idx = 0
    full_output = ""
    flag = None

    flag_pattern = re.compile(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})")
    decoy_keywords = ["decoy", "fake", "honeypot", "dummy", "not_the_flag"]

    for _ in range(100):
        chunk = ""
        while True:
            try:
                data = s.recv(1024)
                if not data:
                    break
                text = data.decode("utf-8", errors="ignore")
                chunk += text
                full_output += text
                print(text, end="", flush=True)

                match = flag_pattern.search(full_output)
                if match:
                    candidate = match.group(1)
                    if not any(k in candidate.lower() for k in decoy_keywords):
                        flag = candidate

                if "(Press Enter to continue...)" in chunk:
                    s.sendall(b"\n")
                    break

                if any(prompt in chunk for prompt in ["[a/b/c]", "[a/b]", "[y/n]", "> "]):
                    if ans_idx < len(answers):
                        ans = answers[ans_idx] + "\n"
                        ans_idx += 1
                        print(f"[*] Sending answer: {ans.strip()}", flush=True)
                        s.sendall(ans.encode("utf-8"))
                        break
            except socket.timeout:
                break

        if not chunk and flag:
            break

    s.close()

    if not flag:
        match = flag_pattern.search(full_output)
        if match:
            candidate = match.group(1)
            if not any(k in candidate.lower() for k in decoy_keywords):
                flag = candidate

    if flag:
        print(f"\n[+] Flag extracted: {flag}", flush=True)
        flag_path = Path(__file__).resolve().parent / "flag.txt"
        flag_path.write_text(flag.strip() + "\n", encoding="utf-8")
        print(f"[+] Flag written to {flag_path}", flush=True)
        return flag
    else:
        print("[-] Flag not found in server response.", flush=True)
        sys.exit(1)


if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{m1113n1um_3d1710n_2ad04d2b}
```
