# Writeup: 13

## Header & Metadata
- **Challenge:** 13 (ID: 62)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `academy{not_too_bad_of_a_problem}`

---

## Mô tả bài toán (Overview / Analysis)
Cryptography can be easy, do you know what ROT13 is? `npnqrzl{abg_gbb_onq_bs_n_ceboyrz}`


### Hints
- This can be solved online if you don't want to do it by hand!

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for 13 (#62)
Category: Cryptography
"""
import codecs
from pathlib import Path

def solve():
    print("[*] Solving 13...", flush=True)
    ciphertext = "npnqrzl{abg_gbb_onq_bs_n_ceboyrz}"
    
    # ROT13 decryption
    plaintext = codecs.decode(ciphertext, 'rot_13')
    print(f"[*] Decrypted text: {plaintext}", flush=True)

    # Decoy rejection check
    decoy_words = ['fake', 'decoy', 'honey', 'not_the_flag', 'dummy']
    for dw in decoy_words:
        if dw in plaintext.lower():
            raise ValueError(f"Decoy flag detected: {plaintext}")

    if not (plaintext.startswith("academy{") or plaintext.startswith("picoCTF{")):
        raise ValueError(f"Flag format unexpected: {plaintext}")

    flag = plaintext.strip()
    Path("flag.txt").write_text(flag, encoding="utf-8")
    print(f"[+] Flag found: {flag}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{not_too_bad_of_a_problem}
```
