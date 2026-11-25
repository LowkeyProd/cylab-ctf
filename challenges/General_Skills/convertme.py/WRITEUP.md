# Writeup: convertme.py

## Header & Metadata
- **Challenge:** convertme.py (ID: 239)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** convertme.py
- **Official Flag:** `academy{4ll_y0ur_b4535_5dbc7d96}`

---

## Mô tả bài toán (Overview / Analysis)
Run the Python script and convert the given number from decimal to binary to
get the flag.
<a href='https://challenge-files.cylabacademy.net/library/53593e943ff7e6cfce8e93c7dd9d414ecb6f51ccc6cd05c0f5648856754ed2a5/convertme.py' download>Download Python script</a>

### Hints
- Look up a decimal to binary number conversion app on the web or use your
  computer's calculator!
- The `str_xor` function does not need to be reverse engineered for this
  challenge.
- If you have Python on your computer, you can download the script normally and
  run it. Otherwise, use the `wget` command in the webshell.
- To use `wget` in the webshell, first right click on the download link and
  select 'Copy Link' or 'Copy Link Address'
- Type everything after the dollar sign in the webshell: `$ wget `, then
  paste the link after the space after `wget` and press enter. This will
  download the script for you in the webshell so you can run it!
- Finally, to run the script, type everything after the dollar sign and then
  press enter: `$ python3 convertme.py`

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for convertme.py (#239)
Category: General Skills
"""
from pathlib import Path
import re

def str_xor(secret, key):
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c, new_key_c) in zip(secret, new_key)])

def solve():
    print("[*] Solving convertme.py...", flush=True)
    flag_enc = chr(0x04) + chr(0x0d) + chr(0x0a) + chr(0x0d) + chr(0x01) + chr(0x18) + chr(0x1c) + chr(0x15) + chr(0x5f) + chr(0x05) + chr(0x08) + chr(0x2a) + chr(0x1c) + chr(0x5e) + chr(0x1e) + chr(0x1b) + chr(0x3b) + chr(0x17) + chr(0x51) + chr(0x5b) + chr(0x58) + chr(0x5c) + chr(0x3b) + chr(0x40) + chr(0x01) + chr(0x0c) + chr(0x08) + chr(0x5e) + chr(0x00) + chr(0x4c) + chr(0x53) + chr(0x13)
    flag = str_xor(flag_enc, 'enkidu')
    print(f"[+] Flag found: {flag}", flush=True)

    # Save to flag.txt
    Path("flag.txt").write_text(flag.strip())
    print("[+] Flag saved to flag.txt", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{4ll_y0ur_b4535_5dbc7d96}
```
