# Writeup: New Vignere

## Header & Metadata
- **Challenge:** New Vignere (ID: 148)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** new_vignere.py
- **Official Flag:** `academy{468293b06253c715005873e333d98dbc}`

---

## Mô tả bài toán (Overview / Analysis)
Another slight twist on a classic, see if you can recover the flag. (Wrap with academy{})
<a href='https://challenge-files.cylabacademy.net/library/257cca318d82cec431ab85a84a041baeb2b1867ab1bce83d75299efb8865003a/new_vignere.py' download>new_vignere.py</a> emfakcakmklfajnnlpekfpkndlmildnmnnljenfckbalpglfnknaonebfcnodkpe

### Hints
- https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher#Cryptanalysis

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for New Vignere (#148)
Category: Cryptography
"""
import string
import sys
from pathlib import Path

LOWERCASE_OFFSET = ord("a")
ALPHABET = string.ascii_lowercase[:16]

def b16_decode(b16):
    res = ""
    for i in range(0, len(b16), 2):
        high = ALPHABET.index(b16[i])
        low = ALPHABET.index(b16[i + 1])
        val = (high << 4) | low
        res += chr(val)
    return res

def solve():
    print("[*] Solving New Vignere...", flush=True)
    ct = "emfakcakmklfajnnlpekfpkndlmildnmnnljenfckbalpglfnknaonebfcnodkpe"

    flag_raw = None
    key_found = None

    for klen in range(1, 15):
        possible_k = []
        for p in range(klen):
            candidates = set(range(16))
            for i in range(len(ct)):
                if i % klen == p:
                    ci = ord(ct[i]) - LOWERCASE_OFFSET
                    if i % 2 == 0:
                        # High nibble must be 3 ('d') or 6 ('g')
                        allowed_k = {(ci - 3) % 16, (ci - 6) % 16}
                        candidates &= allowed_k
                    else:
                        # Low nibble must be in 0..9
                        allowed_k = {(ci - low) % 16 for low in range(10)}
                        candidates &= allowed_k
            possible_k.append(candidates)

        if all(len(c) > 0 for c in possible_k):
            # Enumerate possible keys
            def dfs(pos, curr_key):
                nonlocal flag_raw, key_found
                if flag_raw is not None:
                    return
                if pos == klen:
                    b16 = ""
                    for i, c in enumerate(ct):
                        val = (ord(c) - LOWERCASE_OFFSET - curr_key[i % klen]) % 16
                        b16 += ALPHABET[val]
                    candidate_flag = b16_decode(b16)
                    if all(ch in "abcdef0123456789" for ch in candidate_flag):
                        flag_raw = candidate_flag
                        key_found = "".join(ALPHABET[x] for x in curr_key)
                    return
                for k_val in possible_k[pos]:
                    dfs(pos + 1, curr_key + [k_val])

            dfs(0, [])
            if flag_raw:
                break

    if not flag_raw:
        print("[-] Flag not found!", flush=True)
        return ""

    print(f"[+] Key found: {key_found}", flush=True)
    print(f"[+] Decrypted hex: {flag_raw}", flush=True)

    flag = f"academy{{{flag_raw}}}"
    print(f"[+] Flag: {flag}", flush=True)

    # Save to flag.txt
    flag_file = Path("flag.txt")
    flag_file.write_text(flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Saved flag to {flag_file.resolve()}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{468293b06253c715005873e333d98dbc}
```
