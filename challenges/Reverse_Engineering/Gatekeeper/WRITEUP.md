# Writeup: Gatekeeper

## Header & Metadata
- **Challenge:** Gatekeeper (ID: 731)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `nc xebec.cylabacademy.net 48570`
- **Attached Files:** gatekeeper
- **Official Flag:** `academy{3_digit_hex_GT_999_9509c620}`

---

## Mô tả bài toán (Overview / Analysis)
What’s behind the numeric gate? You only get access if you enter the *right* kind of number.
You can download the program file <a href='https://challenge-files.cylabacademy.net/library/940a95cf085ec08ea07b699edb30f11fed369876f77a6be9e769118a62c39aa9/gatekeeper' download>here</a>.
Reverse the program behavior and find what input grants access to the secret flag. `nc xebec.cylabacademy.net 48570`.

### Hints
- Tools like **Ghidra**, **IDA Free**, or **Radare2** can analyze the binary’s logic.
- The program’s output isn’t straightforward; reversing the string and cleaning out extra text may help you recover the flag.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Gatekeeper (#731)
Category: Reverse Engineering
"""
import re
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 47712
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("HOST=") and line.split("=", 1)[1]:
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    p = int(line.split("=", 1)[1].strip())
                    if p > 0:
                        port = p
                except Exception:
                    pass
    return host, port

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...")
    s = socket.socket()
    s.settimeout(10)
    s.connect((host, port))

    prompt = s.recv(1024).decode(errors="ignore")
    print(f"[*] Received prompt: {prompt.strip()}")

    # Send 3-digit hex number > 999 (0x3e8 = 1000)
    payload = b"3e8\n"
    print(f"[*] Sending payload: {payload.strip().decode()}")
    s.sendall(payload)

    response = s.recv(4096).decode(errors="ignore")
    s.close()
    print(f"[*] Received response: {response.strip()}")

    # Extract obfuscated flag after 'Access granted: '
    m = re.search(r"Access granted:\s*(.+)", response)
    if not m:
        raise ValueError("Could not find 'Access granted:' in response")

    raw_flag_part = m.group(1).strip()
    cleaned = raw_flag_part.replace("ftc_oc_ip", "")
    flag = cleaned[::-1]

    print(f"[+] Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{3_digit_hex_GT_999_9509c620}
```
