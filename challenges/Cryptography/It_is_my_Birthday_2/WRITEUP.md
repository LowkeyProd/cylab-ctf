# Writeup: It is my Birthday 2

## Header & Metadata
- **Challenge:** It is my Birthday 2 (ID: 169)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `http://xebec.cylabacademy.net:23582`
- **Attached Files:** invite.pdf
- **Official Flag:** `academy{h4ppy_b1rthd4y_2_m3_8248ffdd}`

---

## Mô tả bài toán (Overview / Analysis)
My birthday is coming up again, but I want to have a very exclusive party for only the best cryptologists. See if you can solve my challenge, upload 2 valid PDFs that are different but have the same SHA1 hash. They should both have the same 1000 bytes at the end as the original invite.
[http://xebec.cylabacademy.net:23582/](http://xebec.cylabacademy.net:23582/) <a href='https://challenge-files.cylabacademy.net/library/d6bc6ebb622c34b99cb78aa3b1deadb0553191f7ad7836cda3994923adfc2461/invite.pdf' download>invite.pdf</a>

### Hints
- This isn't REALLY a birthday attack problem
- [https://shattered.io/](https://shattered.io/)
- The PDFs cannot be the same
- The PDFs must be valid
- The last 1000 bytes of each PDF must match the last 1000 bytes of the original

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for It is my Birthday 2 (#169)
Category: Cryptography
"""
import hashlib
from pathlib import Path
import re
import sys
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("URL=") and line.split("=", 1)[1]:
                return line.split("=", 1)[1]
            if line.startswith("HOST=") and line.split("=", 1)[1]:
                host = line.split("=", 1)[1]
            if line.startswith("PORT=") and line.split("=", 1)[1]:
                port = line.split("=", 1)[1]
        if 'host' in locals() and 'port' in locals():
            return f"http://{host}:{port}"
    return "http://chatelaine.cylabacademy.net:12997"

def solve():
    base_dir = Path(__file__).resolve().parent
    base_url = get_target_url().rstrip('/')
    upload_url = f"{base_url}/upload"
    print(f"[*] Target URL: {upload_url}", flush=True)

    invite_file = base_dir / "invite.pdf"
    if not invite_file.exists():
        print(f"[-] Missing {invite_file}", flush=True)
        return None

    invite_data = invite_file.read_bytes()
    suffix = invite_data[-1000:]
    print(f"[*] Extracted suffix length: {len(suffix)} bytes", flush=True)

    pdf1_file = base_dir / "shattered-1.pdf"
    pdf2_file = base_dir / "shattered-2.pdf"

    if not pdf1_file.exists() or not pdf2_file.exists():
        print("[-] Missing shattered collision files", flush=True)
        return None

    pdf1_data = pdf1_file.read_bytes()
    pdf2_data = pdf2_file.read_bytes()

    # Append suffix to create valid PDFs matching the challenge constraints
    mod_pdf1 = pdf1_data + suffix
    mod_pdf2 = pdf2_data + suffix

    assert mod_pdf1 != mod_pdf2, "Colliding PDFs must be different"
    sha1_1 = hashlib.sha1(mod_pdf1).hexdigest()
    sha1_2 = hashlib.sha1(mod_pdf2).hexdigest()
    assert sha1_1 == sha1_2, f"SHA-1 collision broken: {sha1_1} != {sha1_2}"
    assert mod_pdf1[-1000:] == suffix and mod_pdf2[-1000:] == suffix, "Suffix mismatch"

    print(f"[*] Verified SHA-1 collision pair: {sha1_1}", flush=True)

    files = {
        'file1': ('invite1.pdf', mod_pdf1, 'application/pdf'),
        'file2': ('invite2.pdf', mod_pdf2, 'application/pdf')
    }

    try:
        r = requests.post(upload_url, files=files, timeout=20)
        print(f"[*] HTTP Status: {r.status_code}", flush=True)

        flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
        matches = flag_pattern.findall(r.text)
        for flag in matches:
            if not any(decoy in flag.lower() for decoy in ['fake', 'decoy', 'honey', 'dummy', 'not_the_flag']):
                print(f"[+] Flag found: {flag}", flush=True)
                flag_file = base_dir / "flag.txt"
                flag_file.write_text(flag.strip() + "\n")
                return flag

        print("[-] Flag not found in server response.", flush=True)
        print(f"[-] Response snippet: {r.text[:500]}", flush=True)
    except Exception as e:
        print(f"[-] Request failed: {e}", flush=True)

    return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{h4ppy_b1rthd4y_2_m3_8248ffdd}
```
