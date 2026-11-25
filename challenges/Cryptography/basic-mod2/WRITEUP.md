# Writeup: basic-mod2

## Header & Metadata
- **Challenge:** basic-mod2 (ID: 254)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** message.txt
- **Official Flag:** `academy{1NV3R53LY_H4RD_FED0A735}`

---

## Mô tả bài toán (Overview / Analysis)
A new modular challenge!
Download the message <a href='https://challenge-files.cylabacademy.net/library/79ab2df83c3efdaa68f8d1d7b4ce3e478bd49e8193ca7002a30ea460743c412c/message.txt' download>here</a>.

Take each number mod 41 and find the modular inverse for the result. Then map
to the following character set: 1-26 are the alphabet, 27-36 are the decimal
digits, and 37 is an underscore.

Wrap your decrypted message in the academy flag format
(i.e. `academy{decrypted_message}`)

### Hints
- Do you know what the modular inverse is?
- The inverse modulo *z* of *x* is the number, *y* that when multiplied by *x*
  is 1 modulo *z*
- It's recommended to use a tool to find the modular inverses

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for basic-mod2 (#254)
Category: Cryptography
"""
from pathlib import Path
import string

def solve():
    print("[*] Solving basic-mod2...", flush=True)
    message_file = Path(__file__).parent / "message.txt"
    with open(message_file, "r") as f:
        content = f.read().strip()

    numbers = [int(x) for x in content.split()]

    # 1-26 are the alphabet, 27-36 are the decimal digits, 37 is underscore
    # Using 1-based indexing
    mapping = {}
    for i, ch in enumerate(string.ascii_uppercase, start=1):
        mapping[i] = ch
    for i, ch in enumerate(string.digits, start=27):
        mapping[i] = ch
    mapping[37] = "_"

    decrypted = []
    for n in numbers:
        mod_val = n % 41
        inv = pow(mod_val, -1, 41)
        decrypted.append(mapping[inv])

    msg = "".join(decrypted)
    flag = f"academy{{{msg}}}"

    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag)
    print(f"[+] Saved flag to {flag_path}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{1NV3R53LY_H4RD_FED0A735}
```
