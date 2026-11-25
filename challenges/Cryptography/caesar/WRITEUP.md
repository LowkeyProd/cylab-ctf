# Writeup: caesar

## Header & Metadata
- **Challenge:** caesar (ID: 64)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** data.enc
- **Official Flag:** `academy{crossingtherubiconvfuyazrb}`

---

## Mô tả bài toán (Overview / Analysis)
Decrypt this message.
Message: <a href='https://challenge-files.cylabacademy.net/library/a934e747e5c05fde57aa329d9f6f79b4113c18908d017e17e2e340f147f6fb81/data.enc' download>message</a>

### Hints
- Caesar cipher [tutorial](https://learncryptography.com/classical-encryption/caesar-cipher)

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for caesar (#64)
Category: Cryptography
"""
import sys
from pathlib import Path

def solve():
    print("[*] Solving caesar...", flush=True)
    enc_path = Path(__file__).parent / "data.enc"
    with open(enc_path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    # The format is academy{...}
    prefix = content[:content.index("{") + 1]
    suffix = content[content.index("}"):]
    ciphertext = content[content.index("{") + 1:content.index("}")]

    shift = 21
    decrypted_inner = "".join(
        chr((ord(c) - ord('a') - shift) % 26 + ord('a')) if 'a' <= c <= 'z' else c
        for c in ciphertext
    )

    flag = f"{prefix}{decrypted_inner}{suffix}"
    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = Path(__file__).parent / "flag.txt"
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag + "\n")

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{crossingtherubiconvfuyazrb}
```
