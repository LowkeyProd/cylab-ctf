# Writeup: Hidden Cipher 2

## Header & Metadata
- **Challenge:** Hidden Cipher 2 (ID: 751)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `nc chatelaine.cylabacademy.net 47511`
- **Attached Files:** hiddencipher2.zip
- **Official Flag:** `academy{m4th_b3h1nd_c1ph3r_d821886f}`

---

## Mô tả bài toán (Overview / Analysis)
The flag is right in front of you... kind of. You just need to solve a basic math problem to see it. But to get the real flag, you’ll have to understand how that math answer is used.
You can download the program files <a href='https://challenge-files.cylabacademy.net/library/25615a6b0204fa43517181f2a03a400cf1fc1f6106d9ff7f27ddc248bc7448dc/hiddencipher2.zip' download>here</a>.
Connect to the program with netcat:
`nc chatelaine.cylabacademy.net 47511`

### Hints
- Focus on what the program does with your correct answer. Is it reused later?
- Disassembling or decompiling tools (Ghidra, IDA) can help reveal the exact transformation on the flag.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Hidden Cipher 2 (#751)
Target dynamically loaded from connection.cfg
"""
import re
import socket
import sys
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 47511
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

def solve():
    host, port = get_target_conn()
    print(f"[*] Target: {host}:{port}", flush=True)

    for attempt in range(5):
        try:
            s = socket.create_connection((host, port), timeout=10)
            data = ""
            while True:
                chunk = s.recv(1024).decode("latin1")
                if not chunk:
                    break
                data += chunk
                if "?" in data:
                    break

            print(f"[*] Received prompt: {data.strip()}", flush=True)
            m = re.search(r"What is (\d+)\s*([\+\-\*])\s*(\d+)\?", data)
            if not m:
                print("[-] Could not parse math question, retrying...", flush=True)
                s.close()
                continue

            n1 = int(m.group(1))
            op = m.group(2)
            n2 = int(m.group(3))

            if op == "+":
                ans = n1 + n2
            elif op == "-":
                ans = n1 - n2
            elif op == "*":
                ans = n1 * n2
            else:
                ans = 0

            print(f"[*] Solved question: {n1} {op} {n2} = {ans}", flush=True)

            if ans == 0:
                print("[-] Answer is 0 (division by zero risk), retrying...", flush=True)
                s.close()
                continue

            s.sendall(f"{ans}\n".encode())

            resp = ""
            while True:
                try:
                    chunk = s.recv(1024).decode("latin1")
                    if not chunk:
                        break
                    resp += chunk
                except socket.timeout:
                    break

            s.close()
            print(f"[*] Raw response:\n{resp}", flush=True)

            numbers = [int(x) for x in re.findall(r"\b\d+\b", resp)]
            if numbers:
                flag = "".join(chr(x // ans) for x in numbers)
                print(f"[+] Recovered text: {flag}", flush=True)
                if "academy{" in flag or "picoCTF{" in flag:
                    m_flag = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", flag)
                    if m_flag:
                        real_flag = m_flag.group(1)
                        print(f"[+] Found Flag: {real_flag}", flush=True)
                        flag_file = Path(__file__).resolve().parent / "flag.txt"
                        flag_file.write_text(real_flag)
                        return real_flag
        except Exception as e:
            print(f"[-] Exception: {e}", flush=True)

    print("[-] Failed to retrieve flag after attempts", flush=True)
    return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{m4th_b3h1nd_c1ph3r_d821886f}
```
