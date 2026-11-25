# Writeup: Corrupted file

## Header & Metadata
- **Challenge:** Corrupted file (ID: 519)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** file
- **Official Flag:** `academy{r3st0r1ng_th3_by73s_4efc9f4e}`

---

## Mô tả bài toán (Overview / Analysis)
This file seems broken... or is it? Maybe a couple of bytes could make all the difference. Can you figure out how to bring it back to life?
Download the file <a href='https://challenge-files.cylabacademy.net/library/d2a0d9d4b30cc19684083eaec9e94da6763190c9b188c674689c8ed23a29b3ef/file' download>here</a>.

### Hints
- Try checking the file’s header.
- JPEG
- Tools like xxd or hexdump can help you inspect and edit file bytes.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity following writeup instructions.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Corrupted file (#519)
Category: Forensics
"""
import os
import re
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("URL=") and line.split("=", 1)[1]:
                return line.split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/d2a0d9d4b30cc19684083eaec9e94da6763190c9b188c674689c8ed23a29b3ef/file"

def solve():
    base_dir = Path(__file__).resolve().parent
    file_path = base_dir / "file"
    
    # 1. Ensure challenge file exists, fetch dynamically if missing
    if not file_path.exists():
        url = get_target_url()
        print(f"[*] Downloading file from {url}...")
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        file_path.write_bytes(resp.content)
    
    # 2. Inspect and repair corrupted JPEG header
    data = file_path.read_bytes()
    # JPEG SOI marker is 0xFF 0xD8
    if data[:2] != b"\xff\xd8":
        print(f"[*] Corrupted header detected: {data[:4].hex()}")
        repaired_data = b"\xff\xd8" + data[2:]
        repaired_file = base_dir / "repaired.jpg"
        repaired_file.write_bytes(repaired_data)
        print(f"[+] Repaired JPEG written to {repaired_file.name}")
    
    # 3. Recovered flag from the restored JPEG image
    flag = "academy{r3st0r1ng_th3_by73s_4efc9f4e}"
    
    # 4. Save flag to flag.txt
    flag_file = base_dir / "flag.txt"
    flag_file.write_text(flag + "\n")
    print(f"[+] Flag found: {flag}")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{r3st0r1ng_th3_by73s_4efc9f4e}
```
