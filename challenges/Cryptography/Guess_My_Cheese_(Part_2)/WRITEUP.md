# Writeup: Guess My Cheese (Part 2)

## Header & Metadata
- **Challenge:** Guess My Cheese (Part 2) (ID: 474)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** cheese_list.txt
- **Official Flag:** `academy{cHeEsY5385a78c}`

---

## Mô tả bài toán (Overview / Analysis)
The imposter was able to fool us last time, so we've strengthened our defenses!

Here's our <a href='https://challenge-files.cylabacademy.net/library/7c5c2a4986828dbc00e7e5a7e010a2af40a61b6e688b881ea72cd98e24f6cb5d/cheese_list.txt' download>list</a> of cheeses.

### Hints
- I heard that *SHA-256* is the best hash function out there!
- Remember Squeexy, we enjoy our cheese with exactly *2 nibbles* of *hexadecimal-character salt*!
- Ever heard of *rainbow tables*?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Thử thách yêu cầu phân tích dữ liệu, khai thác dịch vụ mạng hoặc thuật toán mã hóa để giải mã và khôi phục cờ (flag).

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Guess My Cheese (Part 2) (#474)
Category: Cryptography
"""
import re
import socket
import hashlib
from pathlib import Path

def parse_connection_cfg(cfg_path=None):
    if cfg_path is None:
        cfg_path = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    path = Path(cfg_path)
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line:
                    key, val = line.split("=", 1)
                    config[key.strip()] = val.strip()
    return config

def recv_until(sock, target):
    buf = ""
    while target not in buf:
        chunk = sock.recv(1024).decode("latin1")
        if not chunk:
            break
        buf += chunk
    return buf

def build_rainbow_table(cheese_file=None):
    if cheese_file is None:
        cheese_file = Path(__file__).resolve().parent / "cheese_list.txt"
    print("[*] Precomputing rainbow table...", flush=True)
    table = {}
    with open(cheese_file, "r", encoding="utf-8") as f:
        cheeses = [line.strip() for line in f if line.strip()]

    for orig_cheese in cheeses:
        c_lower = orig_cheese.lower()
        for i in range(256):
            salt = bytes([i])
            h = hashlib.sha256(c_lower.encode("utf-8") + salt).hexdigest()
            table[h] = (orig_cheese, i)

    print(f"[*] Precomputed {len(table)} hashes.", flush=True)
    return table

def solve():
    print("[*] Solving Guess My Cheese (Part 2)...", flush=True)
    config = parse_connection_cfg()
    host = config.get("HOST", "xebec.cylabacademy.net")
    port = int(config.get("PORT", 27967))

    table = build_rainbow_table()

    s = socket.socket()
    s.settimeout(15)
    s.connect((host, port))

    banner = recv_until(s, "What would you like to do?")
    print("[*] Received banner.", flush=True)

    m = re.search(r"Here's my secret cheese -- if you're Squeexy, you'll be able to guess it:\s+([0-9a-f]{64})", banner)
    if not m:
        raise ValueError("Could not find secret cheese hash in banner")
    target_hash = m.group(1).strip()
    print(f"[*] Target hash: {target_hash}", flush=True)

    if target_hash not in table:
        raise ValueError(f"Hash {target_hash} not found in rainbow table!")

    cheese_guess, salt_val = table[target_hash]
    print(f"[*] Cracked cheese: '{cheese_guess}', salt_val: {salt_val} (hex: {salt_val:02x})", flush=True)

    # Send command 'g'
    s.sendall(b"g\n")
    recv_until(s, "So...what's my cheese?")
    print("[*] Prompt received, sending cheese guess...", flush=True)
    s.sendall((cheese_guess.lower() + "\n").encode("utf-8"))

    salt_prompt = recv_until(s, "Annnnd...what's my salt?")
    print("[*] Salt prompt received. Sending salt...", flush=True)
    salt_hex = f"{salt_val:02x}"
    s.sendall((salt_hex + "\n").encode("utf-8"))

    # Receive response
    full_output = ""
    while True:
        try:
            chunk = s.recv(4096).decode("latin1", errors="ignore")
            if not chunk:
                break
            full_output += chunk
            if "academy{" in full_output or "picoCTF{" in full_output:
                break
        except socket.timeout:
            break

    s.close()
    print("[*] Server response:\n" + full_output, flush=True)

    m_flag = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", full_output)
    if m_flag:
        flag = m_flag.group(1)
        print(f"[+] Found flag: {flag}", flush=True)
        with open("flag.txt", "w", encoding="utf-8") as f:
            f.write(flag + "\n")
        return flag
    else:
        print("[-] Flag not found in response.", flush=True)
        return ""

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{cHeEsY5385a78c}
```
