# Writeup: vault-door-training

## Header & Metadata
- **Challenge:** vault-door-training (ID: 7)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** VaultDoorTraining.java
- **Official Flag:** `academy{w4rm1ng_Up_w1tH_jAv4_c02db1ca2a4}`

---

## Mô tả bài toán (Overview / Analysis)
Your mission is to enter Dr. Evil's laboratory and retrieve the blueprints for his Doomsday Project. The laboratory is protected by a series of locked vault doors. Each door is controlled by a computer and requires a password to open. Unfortunately, our undercover agents have not been able to obtain the secret passwords for the vault doors, but one of our junior agents obtained the source code for each vault's computer! You will need to read the source code for each level to figure out what the password is for that vault door. As a warmup, we have created a replica vault in our training facility.

The source code for the training vault is here: <a href='https://challenge-files.cylabacademy.net/library/83cc2880b948e8f4ec4aead98be96ed71b1e83e3525bddac26f4e1030fc740f7/VaultDoorTraining.java' download>VaultDoorTraining.java</a>


### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for vault-door-training (#7)
Category: Reverse Engineering
"""
import re
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/080a285021cd4d6edaff96f54c7eba477b4f450b778c0c129297bf51bbd3d3c8/VaultDoorTraining.java"

def get_source_content():
    local_java = Path(__file__).resolve().parent / "VaultDoorTraining.java"
    if local_java.exists():
        print(f"[*] Reading local file: {local_java}", flush=True)
        return local_java.read_text(encoding="utf-8")
    
    url = get_target_url().rstrip('/')
    print(f"[*] Fetching source from: {url}", flush=True)
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return r.text

def solve():
    content = get_source_content()

    # Determine prefix from substring check, e.g. "academy{" or "picoCTF{"
    prefix_match = re.search(r'substring\("([^"]+)"\.length\(\)', content)
    prefix = prefix_match.group(1) if prefix_match else "academy{"

    # Find the password string compared in checkPassword
    # e.g., return password.equals("w4rm1ng_Up_w1tH_jAv4_1633b42d7f1");
    pw_match = re.search(r'checkPassword\(String\s+password\)\s*\{\s*return\s+password\.equals\("([^"]+)"\);', content)
    if not pw_match:
        # Fallback search for any equals check
        pw_match = re.search(r'password\.equals\("([^"]+)"\)', content)

    if not pw_match:
        print("[-] Could not find password in source code.", flush=True)
        return None

    password = pw_match.group(1)
    flag = f"{prefix}{password}}}"

    # Reject decoys
    for decoy in ['decoy', 'fake', 'honeypot', 'dummy']:
        if decoy in flag.lower():
            print(f"[-] Flag rejected due to decoy keyword: {flag}", flush=True)
            return None

    print(f"[+] Flag found: {flag}", flush=True)
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Flag saved to: {flag_file}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{w4rm1ng_Up_w1tH_jAv4_c02db1ca2a4}
```
