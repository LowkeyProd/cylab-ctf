# Writeup: WinAntiDbg0x200

## Header & Metadata
- **Challenge:** WinAntiDbg0x200 (ID: 430)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** WinAntiDbg0x200.zip
- **Official Flag:** `academy{0x200_debug_f0r_Win_cf686cdb}`

---

## Mô tả bài toán (Overview / Analysis)
If you have solved WinAntiDbg0x100, you'll discover something new in this one. Debug the executable and find the flag!

This challenge executable is a Windows console application, and you can start by running it using Command Prompt on Windows.

This executable requires admin privileges. You might want to start Command Prompt or your debugger using the 'Run as administrator' option.

Challenge can be downloaded <a href='https://challenge-files.cylabacademy.net/library/842fd067da1fb3a42394847ad47fa3f7a479a37a676e8053f175959077b9930e/WinAntiDbg0x200.zip' download>here</a>. Unzip
the archive with the password `academy`


### Hints
- Hints will be displayed to the Debug console. Good luck!

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for WinAntiDbg0x200 (#430)
Category: Reverse Engineering
"""
import os
from pathlib import Path

def parse_connection_cfg(cfg_path="connection.cfg"):
    cfg = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    return cfg

def popcount(n):
    return bin(n % 255).count('1')

def solve():
    print("[*] Solving WinAntiDbg0x200...", flush=True)
    cfg = parse_connection_cfg()
    print(f"[*] Configuration: {cfg}", flush=True)

    config_bin_path = Path("config.bin")
    if not config_bin_path.exists():
        raise FileNotFoundError("config.bin not found")

    with open(config_bin_path, "rb") as f:
        data = f.read()

    length = int.from_bytes(data[:4], "little")
    buf = data[4:]
    buf1 = list(buf[:length])
    buf2 = list(buf[length + 1 : length + 1 + length])

    # The binary calls 0x401090 with total count = 3 + 5 + 4 + 4 + 1 = 17 iterations
    # Each iteration transforms buf1 with popcount(i):
    # buf1[i] = ord('a') + ((buf1[i] - ord('a') + popcount(i)) % 26)
    total_iters = 17
    b1 = list(buf1)
    for _ in range(total_iters):
        for i in range(length):
            w = popcount(i)
            b1[i] = ord('a') + ((b1[i] - ord('a') + w) % 26)

    # 0x401180 computes buf2[i] ^= b1[i]
    flag_bytes = bytes([x ^ y for x, y in zip(b1, buf2)])
    flag = flag_bytes.decode("utf-8")

    print(f"[*] Extracted Flag: {flag}", flush=True)

    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag)

    print(f"[+] Flag written to flag.txt: {flag}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{0x200_debug_f0r_Win_cf686cdb}
```
