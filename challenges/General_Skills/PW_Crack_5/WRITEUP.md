# Writeup: PW Crack 5

## Header & Metadata
- **Challenge:** PW Crack 5 (ID: 249)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** level5.py, level5.flag.txt.enc, level5.hash.bin, dictionary.txt
- **Official Flag:** `academy{h45h_sl1ng1ng_e062d0ff}`

---

## Mô tả bài toán (Overview / Analysis)
Can you crack the password to get the flag?
Download the password checker <a href='https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/level5.py' download>here</a> and you'll
need the encrypted <a href='https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/level5.flag.txt.enc' download>flag</a> and the
<a href='https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/level5.hash.bin' download>hash</a> in the same directory too. Here's a
<a href='https://challenge-files.cylabacademy.net/library/ab8c1cf7e7d8fda84ad80d01a77290b4ea24c6998837de149a179b1216941290/dictionary.txt' download>dictionary</a> with all possible passwords based
on the password conventions we've seen so far.

### Hints
- Opening a file in Python is crucial to using the provided dictionary.
- You may need to trim the whitespace from the dictionary word before hashing.
  Look up the Python string function, `strip`
- The `str_xor` function does not need to be reverse engineered for this
  challenge.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for PW Crack 5 (#249)
Category: General Skills
"""
import hashlib
from pathlib import Path

def str_xor(secret, key):
    # extend key to secret length
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])

def solve():
    print("[*] Solving PW Crack 5...")
    base_dir = Path(__file__).parent
    flag_enc = (base_dir / 'level5.flag.txt.enc').read_bytes().decode('latin1', errors='ignore')
    correct_pw_hash = (base_dir / 'level5.hash.bin').read_bytes()

    dict_path = base_dir / 'dictionary.txt'
    with open(dict_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            pw = line.strip()
            if hashlib.md5(pw.encode()).digest() == correct_pw_hash:
                print(f"[+] Found password: {pw}")
                flag = str_xor(flag_enc, pw)
                print(f"[+] Flag: {flag}")
                (base_dir / 'flag.txt').write_text(flag.strip())
                return flag

    print("[-] Password not found!")
    return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{h45h_sl1ng1ng_e062d0ff}
```
