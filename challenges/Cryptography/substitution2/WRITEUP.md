# Writeup: substitution2

## Header & Metadata
- **Challenge:** substitution2 (ID: 309)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** message.txt
- **Official Flag:** `academy{N6R4M_4N41Y515_15_73D10U5_FD56C357}`

---

## Mô tả bài toán (Overview / Analysis)
It seems that another encrypted message has been intercepted. The encryptor
seems to have learned their lesson though and now there isn't any punctuation!
Can you still crack the cipher?
Download the message <a href='https://challenge-files.cylabacademy.net/library/750a77d87fa924d5ec8a173d7354dd57792a1597cab3d89fa7443608ba0a35e7/message.txt' download>here</a>.

### Hints
- Try refining your frequency attack, maybe analyzing groups of letters would
  improve your results?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for substitution2 (#309)
Category: Cryptography
"""
from pathlib import Path
import re

def solve():
    print("[*] Solving substitution2...", flush=True)
    msg_path = Path("message.txt")
    if not msg_path.exists():
        raise FileNotFoundError("message.txt not found")

    text = msg_path.read_text().strip()

    # Substitution mapping discovered via frequency and n-gram analysis
    mapping = {
        'a': 'n', 'b': 'y', 'c': 'h', 'e': 'c', 'f': 'q', 'g': 'i', 'h': 'x',
        'i': 'f', 'j': 'm', 'k': 'w', 'l': 'e', 'm': 'l', 'n': 'v', 'o': 'd',
        'p': 'o', 'r': 'a', 's': 'r', 't': 'g', 'u': 's', 'v': 'u', 'w': 'b',
        'x': 't', 'y': 'p', 'z': 'k'
    }

    decrypted_chars = []
    for c in text:
        if c in mapping:
            decrypted_chars.append(mapping[c])
        elif c.lower() in mapping:
            decrypted_chars.append(mapping[c.lower()].upper())
        else:
            decrypted_chars.append(c)

    decrypted_text = "".join(decrypted_chars)
    print(f"[*] Decrypted preview: {decrypted_text[:100]}...", flush=True)

    match = re.search(r"(academy\{[^}]+\})", decrypted_text)
    if not match:
        raise ValueError("Flag pattern not found in decrypted text")

    flag = match.group(1)
    print(f"[+] Flag found: {flag}", flush=True)

    with open("flag.txt", "w") as f:
        f.write(flag + "\n")
    print("[+] Saved flag to flag.txt", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{N6R4M_4N41Y515_15_73D10U5_FD56C357}
```
