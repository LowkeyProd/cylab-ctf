# Writeup: repetitions

## Header & Metadata
- **Challenge:** repetitions (ID: 371)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** enc_flag
- **Official Flag:** `academy{base64_n3st3d_dic0d!n8_d0wnl04d3d_c7808bff}`

---

## Mô tả bài toán (Overview / Analysis)
Can you make sense of this file?
Download the file <a href='https://challenge-files.cylabacademy.net/library/4341c214a057d1b6f5e849c64611635897ab3e8d0225540cecd8adc28541d295/enc_flag' download>here</a>.

### Hints
- Multiple decoding is always good.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for repetitions (#371)
Category: General Skills
"""
import base64
import re
import sys
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("URL=") and len(line) > 4:
                return line.split("=", 1)[1]
    return None

def find_flag(text: str):
    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    matches = flag_pattern.findall(text)
    for m in matches:
        lower_m = m.lower()
        if any(decoy in lower_m for decoy in ['decoy', 'fake', 'honeypot', 'dummy']):
            continue
        return m
    return None

def solve():
    content = None
    url = get_target_url()
    if url:
        print(f"[*] Fetching from URL: {url}", flush=True)
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                content = r.content
        except Exception as e:
            print(f"[-] HTTP request failed: {e}, falling back to local file", flush=True)

    if not content:
        local_file = Path(__file__).resolve().parent / "enc_flag"
        if local_file.exists():
            print(f"[*] Reading local enc_flag", flush=True)
            content = local_file.read_bytes()
        else:
            print("[-] No content source found!", flush=True)
            return None

    # Repeatedly decode base64
    cur = content.strip()
    for round_idx in range(50):
        try:
            text = cur.decode('utf-8', errors='ignore')
            flag = find_flag(text)
            if flag:
                print(f"[+] Flag found at round {round_idx}: {flag}", flush=True)
                (Path(__file__).resolve().parent / "flag.txt").write_text(flag + "\n")
                return flag
        except Exception:
            pass

        try:
            cur = base64.b64decode(cur)
        except Exception as e:
            print(f"[-] Base64 decoding stopped at round {round_idx}: {e}", flush=True)
            break

    print("[-] Flag not found", flush=True)
    return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{base64_n3st3d_dic0d!n8_d0wnl04d3d_c7808bff}
```
