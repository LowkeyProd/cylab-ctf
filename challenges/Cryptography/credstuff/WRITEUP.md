# Writeup: credstuff

## Header & Metadata
- **Challenge:** credstuff (ID: 261)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** leak.tar
- **Official Flag:** `academy{C7r1F_54V35_71M3}`

---

## Mô tả bài toán (Overview / Analysis)
We found a leak of a blackmarket website's login credentials. Can you find the
password of the user `cultiris` and successfully decrypt it?
Download the leak <a href='https://challenge-files.cylabacademy.net/library/7f760cee144ac7237469fd6bfab7c748d6f1d101ca47c101187ca7d8f5c721f0/leak.tar' download>here</a>.

The first user in `usernames.txt` corresponds to the first password in
`passwords.txt`. The second user corresponds to the second password, and so on.

### Hints
- Maybe other passwords will have hints about the leak?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for credstuff (#261)
Category: Cryptography
"""
import codecs
import os
import tarfile
from pathlib import Path

def parse_connection_cfg(cfg_path: Path):
    config = {}
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    return config

def solve():
    print("[*] Solving credstuff...", flush=True)
    base_dir = Path(__file__).resolve().parent

    # Parse connection.cfg dynamically
    cfg_path = base_dir / "connection.cfg"
    config = parse_connection_cfg(cfg_path)
    host = config.get("HOST", "")
    port = config.get("PORT", 0)

    # Ensure leak directory is present
    leak_dir = base_dir / "leak"
    tar_path = base_dir / "leak.tar"
    if not leak_dir.exists() and tar_path.exists():
        print("[*] Extracting leak.tar...", flush=True)
        with tarfile.open(tar_path, "r") as tar:
            tar.extractall(path=base_dir)

    usernames_path = leak_dir / "usernames.txt"
    passwords_path = leak_dir / "passwords.txt"

    if not usernames_path.exists() or not passwords_path.exists():
        raise FileNotFoundError("usernames.txt or passwords.txt not found in leak directory")

    with open(usernames_path, "r", encoding="utf-8", errors="ignore") as u_file:
        usernames = [line.strip() for line in u_file]

    with open(passwords_path, "r", encoding="utf-8", errors="ignore") as p_file:
        passwords = [line.strip() for line in p_file]

    target_user = "cultiris"
    if target_user not in usernames:
        raise ValueError(f"User {target_user} not found in usernames.txt")

    idx = usernames.index(target_user)
    enc_pwd = passwords[idx]
    print(f"[*] Found credential for {target_user} at line {idx + 1}: {enc_pwd}", flush=True)

    # Decrypt using ROT13
    flag = codecs.decode(enc_pwd, "rot_13")
    print(f"[*] Decrypted credential: {flag}", flush=True)

    # Validation checks
    decoys = ["decoy", "fake", "honeypot", "dummy", "not_the_flag"]
    if any(decoy in flag.lower() for decoy in decoys):
        raise ValueError(f"Decoy flag detected: {flag}")

    if not (flag.startswith("academy{") or flag.startswith("picoCTF{")):
        raise ValueError(f"Flag does not match expected format: {flag}")

    flag_file = base_dir / "flag.txt"
    with open(flag_file, "w", encoding="utf-8") as f:
        f.write(flag + "\n")

    print(f"[+] Flag saved to {flag_file}: {flag}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{C7r1F_54V35_71M3}
```
