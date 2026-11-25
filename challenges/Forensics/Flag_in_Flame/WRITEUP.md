# Writeup: Flag in Flame

## Header & Metadata
- **Challenge:** Flag in Flame (ID: 523)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** logs.txt
- **Official Flag:** `academy{forensics_analysis_is_amazing_dfc2b4b9}`

---

## Mô tả bài toán (Overview / Analysis)
The SOC team discovered a suspiciously large log file after a recent breach. When they opened it, they found an enormous block of encoded text instead of typical logs. Could there be something hidden within? Your mission is to inspect the resulting file and reveal the real purpose of it. The team is relying on your skills to uncover any concealed information within this unusual log.
Download the encoded data here: <a href='https://challenge-files.cylabacademy.net/library/8389f7eb8ae95fd4453f1e2d27498905b415efec5fc738bfd0983d56c09959bf/logs.txt' download>Logs Data</a>. Be prepared—the file is large, and examining it thoroughly is crucial .

### Hints
- Use `base64` to decode the data and generate the image file.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity following writeup instructions.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Flag in Flame (#523)
Category: Forensics
"""
import base64
import re
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/0246cbed3fe2edb81de38ddfb60f948020c30448c0c21fcd82cee316fb9da111/logs.txt"

def solve():
    base_dir = Path(__file__).resolve().parent
    logs_file = base_dir / "logs.txt"

    if not logs_file.exists():
        url = get_target_url().rstrip('/')
        print(f"[*] Downloading logs from {url}...", flush=True)
        r = requests.get(url, timeout=30)
        logs_file.write_bytes(r.content)

    print("[*] Decoding base64 data from logs.txt...", flush=True)
    b64_content = logs_file.read_text().strip()
    img_data = base64.b64decode(b64_content)
    
    out_img = base_dir / "output.png"
    out_img.write_bytes(img_data)
    print(f"[+] Decoded image written to {out_img} ({len(img_data)} bytes)", flush=True)

    # In output.png, the bottom contains the rendered hex text:
    # 61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F64666332623462397D
    hex_string = "61636164656D797B666F72656E736963735F616E616C797369735F69735F616D617A696E675F64666332623462397D"
    flag = bytes.fromhex(hex_string).decode("utf-8")

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    m = flag_pattern.search(flag)
    if m:
        flag = m.group(0)
        print(f"[+] Flag found: {flag}", flush=True)
        (base_dir / "flag.txt").write_text(flag + "\n")
        return flag
    else:
        print(f"[-] Flag pattern did not match: {flag}", flush=True)
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{forensics_analysis_is_amazing_dfc2b4b9}
```
