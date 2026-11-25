# Writeup: bytemancy 1

## Header & Metadata
- **Challenge:** bytemancy 1 (ID: 762)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `nc xebec.cylabacademy.net 36048`
- **Attached Files:** app.py
- **Official Flag:** `academy{h0w_m4ny_e's???_17ac1ce5}`

---

## Mô tả bài toán (Overview / Analysis)
Can you conjure the right bytes?
The program's source code can be downloaded <a href='https://challenge-files.cylabacademy.net/library/04db6b1651f9607ce668e4e932e17f9933828c6b728ba327a13ab67552cb7ef0/app.py' download>here</a>.
Connect to the program with netcat:

`$ nc xebec.cylabacademy.net 36048`

### Hints
- No copy-pasta, please - use Python!

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
import socket
import re
import sys
from pathlib import Path

# Set stdout to UTF-8 and unbuffered
sys.stdout.reconfigure(encoding='utf-8', line_buffering=True)

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 36048
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

def recv_until(sock, delimiter=b"==> "):
    buffer = b""
    while delimiter not in buffer:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buffer += chunk
    return buffer

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)
    
    sock = socket.create_connection((host, port), timeout=15)
    
    # Receive banner and prompt
    initial_data = recv_until(sock, b"==> ")
    text = initial_data.decode("utf-8", errors="ignore")
    print(f"[+] Received prompt:\n{text}", flush=True)
    
    # Parse prompt for ASCII decimal and count
    match = re.search(r"ASCII DECIMAL\s+(\d+)\s+(\d+)\s+times", text)
    if not match:
        print("[-] Could not parse prompt pattern, falling back to 101 x 1751", flush=True)
        char_code = 101
        count = 1751
    else:
        char_code = int(match.group(1))
        count = int(match.group(2))
        print(f"[+] Extracted: ASCII code {char_code} ('{chr(char_code)}'), repeat {count} times", flush=True)
    
    payload = (chr(char_code) * count) + "\n"
    print(f"[*] Sending payload (length: {len(payload.strip())})...", flush=True)
    sock.sendall(payload.encode("utf-8"))
    
    # Read remaining response
    response = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break
        except Exception:
            break
    
    result_text = response.decode("utf-8", errors="ignore")
    print(f"[+] Server response:\n{result_text}", flush=True)
    sock.close()
    
    # Search for flag
    flag_match = re.search(r"(?:academy|picoCTF)\{[^}\s]+\}", result_text)
    if flag_match:
        flag = flag_match.group(0)
        # Check against decoys
        for decoy in ['fake', 'decoy', 'honeypot', 'dummy']:
            if decoy in flag.lower():
                print(f"[-] Decoy flag rejected: {flag}", flush=True)
                return
        print(f"[!] FLAG FOUND: {flag}", flush=True)
        flag_path = Path(__file__).resolve().parent / "flag.txt"
        flag_path.write_text(flag, encoding="utf-8")
        print(f"[+] Saved flag to {flag_path}", flush=True)
    else:
        print("[-] No flag found in response.", flush=True)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{h0w_m4ny_e's???_17ac1ce5}
```
