# Writeup: bytemancy 0

## Header & Metadata
- **Challenge:** bytemancy 0 (ID: 742)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `nc chatelaine.cylabacademy.net 17225`
- **Attached Files:** app.py
- **Official Flag:** `academy{pr1n74813_ch4r5_1bf9257c}`

---

## Mô tả bài toán (Overview / Analysis)
Can you conjure the right bytes?
The program's source code can be downloaded <a href='https://challenge-files.cylabacademy.net/library/dc84ad983608656c0750fa999cbc7e9dbab8d65355b6cda6cc5e95df0c2a4342/app.py' download>here</a>.
Connect to the program with netcat:

`$ nc chatelaine.cylabacademy.net 17225`

### Hints
- Solving this with a one-liner will help with the next challenge in this series

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
import socket
import re
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

def get_connection_info():
    cfg_path = os.path.join(os.path.dirname(__file__), 'connection.cfg')
    host = None
    port = None
    if os.path.exists(cfg_path):
        with open(cfg_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('HOST='):
                    host = line.split('=', 1)[1].strip()
                elif line.startswith('PORT='):
                    port = int(line.split('=', 1)[1].strip())
    return host, port

def solve():
    host, port = get_connection_info()
    print(f"Connecting to {host}:{port}...", flush=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # Read until prompt or receive banner
    data = b""
    while b"==>" not in data:
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk

    print(f"Received banner:\n{data.decode('utf-8', errors='ignore')}", flush=True)

    # Send 'eee\n' (\x65\x65\x65)
    s.sendall(b"eee\n")

    response = b""
    while True:
        chunk = s.recv(1024)
        if not chunk:
            break
        response += chunk
        # Check if flag is in response
        if b"}" in response:
            break

    s.close()
    full_text = response.decode('utf-8', errors='ignore')
    print(f"Response:\n{full_text}", flush=True)

    match = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', full_text)
    if match:
        flag = match.group(1)
        print(f"Extracted Flag: {flag}", flush=True)
        # Check for decoy
        for bad in ['decoy', 'fake', 'honeypot', 'dummy']:
            if bad in flag.lower():
                print(f"Warning: Flag contains {bad}, possible decoy!", flush=True)
                return
        with open("flag.txt", "w") as f:
            f.write(flag)
        print("Flag written to flag.txt", flush=True)
    else:
        print("Flag not found in response!", flush=True)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{pr1n74813_ch4r5_1bf9257c}
```
