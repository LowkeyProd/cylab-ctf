# Writeup: PW Crack 3

## Header & Metadata
- **Challenge:** PW Crack 3 (ID: 247)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** level3.py, level3.flag.txt.enc, level3.hash.bin
- **Official Flag:** `academy{m45h_fl1ng1ng_f684152a}`

---

## Mô tả bài toán (Overview / Analysis)
Can you crack the password to get the flag?
Download the password checker <a href='https://challenge-files.cylabacademy.net/library/ae8548417223f50bd8a748c28e60fc688e1426cc7be7b09142456c1427def2c3/level3.py' download>here</a> and you'll
need the encrypted <a href='https://challenge-files.cylabacademy.net/library/ae8548417223f50bd8a748c28e60fc688e1426cc7be7b09142456c1427def2c3/level3.flag.txt.enc' download>flag</a> and the
<a href='https://challenge-files.cylabacademy.net/library/ae8548417223f50bd8a748c28e60fc688e1426cc7be7b09142456c1427def2c3/level3.hash.bin' download>hash</a> in the same directory too.

There are 7 potential passwords with 1 being correct. You can find these by
examining the password checker script.

### Hints
- To view the level3.hash.bin file in the webshell, do: `$ bvi level3.hash.bin`
- To exit `bvi` type `:q` and press enter.
- The `str_xor` function does not need to be reverse engineered for this
  challenge.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity following writeup instructions.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for PW Crack 3 (#247)
Category: General Skills
"""
import hashlib
from pathlib import Path

def str_xor(secret, key):
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])

def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()

def solve():
    print("[*] Solving PW Crack 3...")
    base_dir = Path(__file__).resolve().parent
    flag_enc = (base_dir / "level3.flag.txt.enc").read_bytes()
    correct_pw_hash = (base_dir / "level3.hash.bin").read_bytes()

    pos_pw_list = ["f09e", "4dcf", "87ab", "dba8", "752e", "3961", "f159"]
    
    flag = ""
    for pw in pos_pw_list:
        if hash_pw(pw) == correct_pw_hash:
            print(f"[+] Found correct password: {pw}")
            flag = str_xor(flag_enc.decode(), pw).strip()
            break

    if not flag:
        raise ValueError("Password not found among candidate list!")

    print(f"[+] Flag found: {flag}")
    (base_dir / "flag.txt").write_text(flag + "\n", encoding="utf-8")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{m45h_fl1ng1ng_f684152a}
```
