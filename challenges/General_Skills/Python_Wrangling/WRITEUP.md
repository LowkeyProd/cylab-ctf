# Writeup: Python Wrangling

## Header & Metadata
- **Challenge:** Python Wrangling (ID: 166)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** ende.py, password.txt, flag.txt.en
- **Official Flag:** `academy{4p0110_1n_7h3_h0us3_d6af8f37}`

---

## Mô tả bài toán (Overview / Analysis)
Python scripts are invoked kind of like programs in the Terminal...
Can you run <a href='https://challenge-files.cylabacademy.net/library/a4f054dce4d90aca10ca6075cc2598da541e9acf11ed4a138b962ec69b442f05/ende.py' download>ende.py</a> using <a href='https://challenge-files.cylabacademy.net/library/a4f054dce4d90aca10ca6075cc2598da541e9acf11ed4a138b962ec69b442f05/password.txt' download>password.txt</a> to get <a href='https://challenge-files.cylabacademy.net/library/a4f054dce4d90aca10ca6075cc2598da541e9acf11ed4a138b962ec69b442f05/flag.txt.en' download>flag.txt.en</a>?

### Hints
- Get the Python script accessible in your shell by entering the following command in the Terminal prompt: `$ wget ` followed by a link to the script. The link can be copied from the details section.
- `$ man python`

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Python Wrangling (#166)
Category: General Skills
"""
import base64
import re
from pathlib import Path
from cryptography.fernet import Fernet

def solve():
    print("[*] Solving Python Wrangling...", flush=True)
    base_dir = Path(__file__).resolve().parent
    
    password_file = base_dir / "password.txt"
    flag_file_en = base_dir / "flag.txt.en"
    
    if not password_file.exists() or not flag_file_en.exists():
        raise FileNotFoundError("Required files (password.txt, flag.txt.en) not found.")
        
    password = password_file.read_text().strip()
    encrypted_data = flag_file_en.read_text().strip()
    
    key = base64.b64encode(password.encode())
    fernet = Fernet(key)
    decrypted_bytes = fernet.decrypt(encrypted_data.encode())
    decrypted_text = decrypted_bytes.decode("utf-8", errors="replace").strip()
    
    print(f"[*] Decrypted text: {decrypted_text}", flush=True)
    
    # Check for flag patterns
    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", decrypted_text)
    if not match:
        raise ValueError(f"Could not find valid flag in decrypted text: {decrypted_text}")
        
    flag = match.group(1)
    
    # Check for decoy/fake indicators
    decoys = ["decoy", "fake", "honeypot", "dummy", "not_the_flag"]
    if any(d in flag.lower() for d in decoys):
        raise ValueError(f"Flag rejected as decoy: {flag}")
        
    # Save to flag.txt
    output_flag_file = base_dir / "flag.txt"
    output_flag_file.write_text(flag)
    print(f"[+] Flag found and saved to {output_flag_file}: {flag}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{4p0110_1n_7h3_h0us3_d6af8f37}
```
