# Writeup: MacroHard WeakEdge

## Header & Metadata
- **Challenge:** MacroHard WeakEdge (ID: 130)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** Forensics_is_fun.pptm
- **Official Flag:** `academy{D1d_u_kn0w_ppts_r_z1p5}`

---

## Mô tả bài toán (Overview / Analysis)
I've hidden a flag in this file. Can you find it?
<a href='https://challenge-files.cylabacademy.net/library/ef35dfe613527d28fe872d94179b53bc1a0497ddecf57e51d160c910be3a8e8a/Forensics_is_fun.pptm' download>Forensics_is_fun.pptm</a>

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for MacroHard WeakEdge (#130)
Category: Forensics
"""
import base64
import re
import sys
import zipfile
from pathlib import Path

def solve():
    print("[*] Solving MacroHard WeakEdge...", flush=True)
    
    pptm_path = Path("Forensics_is_fun.pptm")
    if not pptm_path.exists():
        raise FileNotFoundError(f"{pptm_path} not found.")

    with zipfile.ZipFile(pptm_path, 'r') as z:
        # ppt/slideMasters/hidden contains the encoded flag
        raw_hidden = z.read("ppt/slideMasters/hidden").strip()
        cleaned_b64 = raw_hidden.replace(b' ', b'').replace(b'\n', b'').replace(b'\r', b'')
        padding = (4 - len(cleaned_b64) % 4) % 4
        cleaned_b64 += b'=' * padding
        decoded = base64.b64decode(cleaned_b64).decode('utf-8', errors='ignore')
        print(f"[*] Decoded hidden content: {decoded}", flush=True)
        
        match = re.search(r'(academy\{[^\}]+\}|picoCTF\{[^\}]+\})', decoded)
        if not match:
            raise ValueError(f"Flag pattern not found in: {decoded}")
        
        flag = match.group(1)
        for bad in ['decoy', 'fake', 'honeypot', 'dummy']:
            if bad in flag.lower():
                raise ValueError(f"Decoy flag detected: {flag}")

    print(f"[+] Flag found: {flag}", flush=True)
    with open("flag.txt", "w") as f:
        f.write(flag + "\n")
    print(f"[+] Flag saved to flag.txt", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{D1d_u_kn0w_ppts_r_z1p5}
```
