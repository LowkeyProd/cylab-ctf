# Writeup: basic-mod1

## Header & Metadata
- **Challenge:** basic-mod1 (ID: 253)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** message.txt
- **Official Flag:** `academy{R0UND_N_R0UND_81CE8A51}`

---

## Mô tả bài toán (Overview / Analysis)
We found this weird message being passed around on the servers, we think we
have a working decryption scheme.
Download the message <a href='https://challenge-files.cylabacademy.net/library/23b095a85da350dcda44aefdf5a62785a023f5d4570374d08eef71aefd096f7f/message.txt' download>here</a>.

Take each number mod 37 and map it to the following character set: 0-25 is the
alphabet (uppercase), 26-35 are the decimal digits, and 36 is an underscore.

Wrap your decrypted message in the academy flag format
(i.e. `academy{decrypted_message}`)

### Hints
- Do you know what `mod 37` means?
- `mod 37` means modulo 37. It gives the remainder of a number after being
  divided by 37.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for basic-mod1 (#253)
Category: Cryptography
"""
from pathlib import Path
import string

def solve():
    print("[*] Solving basic-mod1...", flush=True)
    message_file = Path(__file__).parent / "message.txt"
    with open(message_file, "r") as f:
        content = f.read().strip()
    
    numbers = [int(x) for x in content.split()]
    
    # 0-25 is uppercase alphabet, 26-35 are digits 0-9, 36 is underscore
    charset = string.ascii_uppercase + string.digits + "_"
    
    decrypted = "".join(charset[n % 37] for n in numbers)
    flag = f"academy{{{decrypted}}}"
    
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
academy{R0UND_N_R0UND_81CE8A51}
```
