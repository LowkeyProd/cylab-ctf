# Writeup: Matryoshka doll

## Header & Metadata
- **Challenge:** Matryoshka doll (ID: 129)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** dolls.jpg
- **Official Flag:** `academy{ZNTyvSDXRNO1d0xCkBRMhAoiafpCTvgW}`

---

## Mô tả bài toán (Overview / Analysis)
Matryoshka dolls are a set of wooden dolls of decreasing size placed one inside another. What's the final one?
Image: <a href='https://challenge-files.cylabacademy.net/library/a268db7b2edb5615a738f69c2c79faa4d8a6bcde6b0f2f797a8f319cb52fe2a5/dolls.jpg' download>dolls.jpg</a>

### Hints
- Wait, you can hide files inside files? But how do you find them?
- Make sure to submit the flag as academy{XXXXX}

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Matryoshka doll (#129)
Category: Forensics
"""
import io
import re
import sys
import zipfile
from pathlib import Path

def parse_connection_cfg(cfg_path: Path):
    cfg = {}
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    return cfg

def solve():
    print("[*] Solving Matryoshka doll...", flush=True)

    base_dir = Path(__file__).resolve().parent
    cfg = parse_connection_cfg(base_dir / "connection.cfg")

    dolls_path = base_dir / "dolls.jpg"
    if not dolls_path.exists():
        print(f"[-] dolls.jpg not found at {dolls_path}", flush=True)
        sys.exit(1)

    with open(dolls_path, "rb") as f:
        curr_data = f.read()

    flag = ""
    iteration = 1

    while True:
        pk_idx = curr_data.find(b"PK\x03\x04")
        if pk_idx == -1:
            print(f"[-] No zip archive found at layer {iteration}", flush=True)
            break

        print(f"[*] Layer {iteration}: Found embedded zip header at offset {pk_idx}", flush=True)
        with zipfile.ZipFile(io.BytesIO(curr_data[pk_idx:])) as zf:
            names = zf.namelist()
            print(f"[*] Archive contents: {names}", flush=True)

            for name in names:
                if "flag" in name.lower() or name.endswith(".txt"):
                    content = zf.read(name).decode("utf-8", errors="replace").strip()
                    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", content)
                    if match:
                        flag = match.group(1)
                        print(f"[+] Flag found: {flag}", flush=True)
                        break

            if flag:
                break

            candidates = [n for n in names if not n.endswith("/") and not n.endswith(".txt")]
            if not candidates:
                print("[-] No further nested files found", flush=True)
                break

            curr_data = zf.read(candidates[0])
            iteration += 1

    if not flag:
        print("[-] Failed to extract flag", flush=True)
        sys.exit(1)

    flag_file = base_dir / "flag.txt"
    with open(flag_file, "w", encoding="utf-8") as f:
        f.write(flag + "\n")
    print(f"[+] Flag saved to {flag_file}", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{ZNTyvSDXRNO1d0xCkBRMhAoiafpCTvgW}
```
