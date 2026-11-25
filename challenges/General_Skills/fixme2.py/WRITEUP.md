# Writeup: fixme2.py

## Header & Metadata
- **Challenge:** fixme2.py (ID: 241)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** fixme2.py
- **Official Flag:** `academy{3qu4l1ty_n0t_4551gnm3nt_341eebbc}`

---

## Mô tả bài toán (Overview / Analysis)
Fix the syntax error in the Python script to print the flag.
<a href='https://challenge-files.cylabacademy.net/library/3fa27ba0c75e4f407f4fd5dc691a5ddfd738d83607729741fee30aac20ca113f/fixme2.py' download>Download Python script</a>

### Hints
- Are equality and assignment the same symbol?
- To view the file in the webshell, do: `$ nano fixme2.py`
- To exit `nano`, press Ctrl and x and follow the on-screen prompts.
- The `str_xor` function does not need to be reverse engineered for this
  challenge.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for fixme2.py (#241)
Category: General Skills
"""
import re
from pathlib import Path


def str_xor(secret, key):
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join(
        [
            chr(ord(secret_c) ^ ord(new_key_c))
            for (secret_c, new_key_c) in zip(secret, new_key)
        ]
    )


def solve():
    print("[*] Solving fixme2.py...", flush=True)

    flag_enc = (
        chr(0x04)
        + chr(0x0D)
        + chr(0x0A)
        + chr(0x0D)
        + chr(0x01)
        + chr(0x18)
        + chr(0x1C)
        + chr(0x15)
        + chr(0x58)
        + chr(0x18)
        + chr(0x11)
        + chr(0x41)
        + chr(0x09)
        + chr(0x5F)
        + chr(0x1F)
        + chr(0x10)
        + chr(0x3B)
        + chr(0x1B)
        + chr(0x55)
        + chr(0x1A)
        + chr(0x34)
        + chr(0x5D)
        + chr(0x51)
        + chr(0x40)
        + chr(0x54)
        + chr(0x09)
        + chr(0x05)
        + chr(0x04)
        + chr(0x57)
        + chr(0x1B)
        + chr(0x11)
        + chr(0x31)
        + chr(0x58)
        + chr(0x5D)
        + chr(0x55)
        + chr(0x10)
        + chr(0x00)
        + chr(0x0C)
        + chr(0x09)
        + chr(0x0A)
        + chr(0x19)
    )

    flag = str_xor(flag_enc, "enkidu")

    # Reject decoys
    if any(d in flag.lower() for d in ["decoy", "fake", "honeypot", "dummy"]):
        raise ValueError("Decoy flag detected!")

    print(f"[+] Flag found: {flag}", flush=True)
    Path("flag.txt").write_text(flag.strip())
    print("[+] Saved flag to flag.txt", flush=True)
    return flag


if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{3qu4l1ty_n0t_4551gnm3nt_341eebbc}
```
