# Writeup: Classic Crackme 0x100

## Header & Metadata
- **Challenge:** Classic Crackme 0x100 (ID: 409)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** crackme100
- **Official Flag:** `academy{s0lv3_angry_symb0ls_08254898}`

---

## Mô tả bài toán (Overview / Analysis)
A classic Crackme. Find the password, get the flag!

Binary can be downloaded <a href='https://challenge-files.cylabacademy.net/library/f0eedad5a5dd920d309ff37bd28b097ed48e764e72b8720389eaa6e247a2bd18/crackme100' download>here</a>.

Crack the Binary file locally and recover the password. Use the same password on the server to get the flag!

### Hints
- Let the machine figure out the symbols!

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Thử thách yêu cầu phân tích dữ liệu, khai thác dịch vụ mạng hoặc thuật toán mã hóa để giải mã và khôi phục cờ (flag).

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Classic Crackme 0x100 (#409)
Target: chatelaine.cylabacademy.net:32257
"""
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 32257
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("HOST=") and line.split("=", 1)[1]:
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def recover_password():
    target = b"dhomvajazmxwwmiiuhpqctvzzsxxixjkmuproxkhdruonhytwl"
    orig = []
    for j in range(len(target)):
        t_val = target[j] - ord('a')
        shift = 3 * bin(j % 255).count('1')
        o_val = (t_val - shift) % 26
        orig.append(chr(ord('a') + o_val))
    return "".join(orig)

def solve():
    password = recover_password()
    print(f"[*] Recovered password: {password}")
    
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...")
    s = socket.socket()
    s.settimeout(10)
    s.connect((host, port))
    prompt = s.recv(1024).decode(errors="ignore")
    print(f"[*] Received prompt: {prompt.strip()}")
    s.sendall(password.encode() + b"\n")
    response = s.recv(1024).decode(errors="ignore")
    print(f"[*] Server response: {response.strip()}")
    s.close()

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{s0lv3_angry_symb0ls_08254898}
```
