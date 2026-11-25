# Writeup: Safe Opener

## Header & Metadata
- **Challenge:** Safe Opener (ID: 294)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `https://challenge-files.cylabacademy.net/library/607b4b8ff5398b4844e4c669686ada9e9535afb5440487266e4895f768af4683/SafeOpener.java`
- **Attached Files:** SafeOpener.java
- **Official Flag:** `academy{pl3as3_l3t_m3_1nt0_th3_saf3}`

---

## Mô tả bài toán (Overview / Analysis)
Can you open this safe?
I forgot the key to my safe but this <a href='https://challenge-files.cylabacademy.net/library/607b4b8ff5398b4844e4c669686ada9e9535afb5440487266e4895f768af4683/SafeOpener.java' download>program</a>
is supposed to help me with retrieving the lost key. Can you help me unlock my
safe?

Put the password you recover into the academy flag format like:

`academy{password}`

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
import base64
import re
import sys
from pathlib import Path

def solve():
    java_file = Path(__file__).resolve().parent / "SafeOpener.java"
    if not java_file.exists():
        print(f"[-] SafeOpener.java not found", flush=True)
        return None

    content = java_file.read_text(encoding="utf-8")
    
    # Extract base64 encodedkey string
    match = re.search(r'encodedkey\s*=\s*["\']([A-Za-z0-9+/=]+)["\']', content)
    if not match:
        print("[-] Could not find encodedkey in SafeOpener.java", flush=True)
        return None

    encoded_key = match.group(1)
    print(f"[*] Found encoded key: {encoded_key}", flush=True)

    # Base64 decode
    decoded_bytes = base64.b64decode(encoded_key)
    password = decoded_bytes.decode("utf-8")
    print(f"[*] Decoded password: {password}", flush=True)

    # Validate against decoys
    for bad in ["decoy", "fake", "honeypot", "dummy"]:
        if bad in password.lower():
            print(f"[-] Decoy detected: {password}", flush=True)
            return None

    flag = f"academy{{{password}}}"
    print(f"[+] Flag recovered: {flag}", flush=True)

    # Store into flag.txt
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag + "\n", encoding="utf-8")
    print(f"[+] Flag written to {flag_file.name}", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{pl3as3_l3t_m3_1nt0_th3_saf3}
```
