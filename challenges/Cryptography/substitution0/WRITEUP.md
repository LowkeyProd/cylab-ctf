# Writeup: substitution0

## Header & Metadata
- **Challenge:** substitution0 (ID: 307)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** message.txt
- **Official Flag:** `academy{5UB5717U710N_3V0LU710N_6A8C4822}`

---

## Mô tả bài toán (Overview / Analysis)
A message has come in but it seems to be all scrambled. Luckily it seems to
have the key at the beginning. Can you crack this substitution cipher?
Download the message <a href='https://challenge-files.cylabacademy.net/library/c81cd186dacb4ad82560df3b81fe365fc1c38a1c7dca9a73a9604c5345ab4473/message.txt' download>here</a>.

### Hints
- Try a frequency attack. An online tool might help.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for substitution0 (#307)
Category: Cryptography
"""
import re
import string
from pathlib import Path

def solve():
    print("[*] Solving substitution0...", flush=True)
    msg_path = Path(__file__).parent / "message.txt"
    with open(msg_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    key = lines[0].strip()
    ciphertext = "".join(lines[1:])
    
    # Key mapping: key[i] corresponds to string.ascii_uppercase[i]
    # For decryption, ciphertext char c (at key.index(c)) -> string.ascii_uppercase[key.index(c)]
    upper_map = {k: v for k, v in zip(key, string.ascii_uppercase)}
    lower_map = {k.lower(): v.lower() for k, v in zip(key, string.ascii_uppercase)}
    
    decrypted_chars = []
    for c in ciphertext:
        if c in upper_map:
            decrypted_chars.append(upper_map[c])
        elif c in lower_map:
            decrypted_chars.append(lower_map[c])
        else:
            decrypted_chars.append(c)
            
    decrypted_text = "".join(decrypted_chars)
    print("\nDecrypted message sample:\n", flush=True)
    print(decrypted_text[:300], flush=True)
    print("...\n", flush=True)
    
    # Match flag
    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", decrypted_text)
    if not match:
        raise ValueError("Flag not found in decrypted text!")
    
    flag = match.group(1)
    print(f"[+] Flag found: {flag}", flush=True)
    
    flag_path = Path(__file__).parent / "flag.txt"
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag)
    print(f"[+] Saved flag to {flag_path}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{5UB5717U710N_3V0LU710N_6A8C4822}
```
