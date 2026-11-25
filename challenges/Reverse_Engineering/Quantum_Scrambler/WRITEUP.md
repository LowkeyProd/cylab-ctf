# Writeup: Quantum Scrambler

## Header & Metadata
- **Challenge:** Quantum Scrambler (ID: 479)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `nc chatelaine.cylabacademy.net 19972`
- **Attached Files:** quantum_scrambler.py
- **Official Flag:** `academy{python_is_weird420f19f2}`

---

## Mô tả bài toán (Overview / Analysis)
We invented a new cypher that uses "quantum entanglement" to encode the flag. Do
you have what it takes to decode it?
Connect to the program with netcat:

`$ nc chatelaine.cylabacademy.net 19972`

The program's source code can be downloaded <a href='https://challenge-files.cylabacademy.net/library/41ec8a99ce7cadb277af7b0c09743624566ce4fd2bd03e2483b848696a39cdff/quantum_scrambler.py' download>here</a>.

### Hints
- Run `eval` on the cypher to interpret it as a python object
- Print the outer list one object per line
- Feed in a known plaintext through the scrambler

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Quantum Scrambler (#479)
"""
import ast
import os
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 19972
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
    print(f"[*] Connecting to {host}:{port}...", flush=True)
    
    s = socket.create_connection((host, port))
    raw_data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        raw_data += chunk
    s.close()
    
    text = raw_data.decode("utf-8", errors="ignore").strip()
    print(f"[*] Received {len(text)} characters of data.", flush=True)
    
    # Parse the cypher representation
    cypher = ast.literal_eval(text)
    
    # Extract the top-level string hex values in order
    flag_chars = []
    for item in cypher:
        for x in item:
            if isinstance(x, str):
                flag_chars.append(chr(int(x, 16)))
                
    flag = "".join(flag_chars)
    print(f"[+] Flag found: {flag}", flush=True)
    
    # Verify flag pattern and absence of decoy strings
    assert "academy{" in flag or "picoCTF{" in flag, "Invalid flag pattern!"
    for decoy in ["fake", "decoy", "honey", "not_the_flag", "dummy"]:
        assert decoy not in flag.lower(), f"Decoy flag detected: {decoy}"
        
    flag_path = Path(__file__).resolve().parent / "flag.txt"
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag + "\n")
    print(f"[+] Flag successfully written to {flag_path}", flush=True)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{python_is_weird420f19f2}
```
