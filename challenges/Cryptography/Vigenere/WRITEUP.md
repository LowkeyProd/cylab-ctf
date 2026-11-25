# Writeup: Vigenere

## Header & Metadata
- **Challenge:** Vigenere (ID: 316)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** cipher.txt
- **Official Flag:** `academy{D0NT_US3_V1G3N3R3_C1PH3R_4a372077}`

---

## Mô tả bài toán (Overview / Analysis)
Can you decrypt this message?
Decrypt this <a href='https://challenge-files.cylabacademy.net/library/7e1288d31bc6645f95d07bcf09caaf93210591ba082ba0f14490f0767ad7fd33/cipher.txt' download>message</a> using this key "CYLAB".

### Hints
- https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity following writeup instructions.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Vigenere (#316)
Category: Cryptography
"""
from pathlib import Path

def decrypt_vigenere(ciphertext: str, key: str) -> str:
    plaintext = []
    key_idx = 0
    key = key.upper()
    for ch in ciphertext:
        if ch.isupper():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            plaintext.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
            key_idx += 1
        elif ch.islower():
            shift = ord(key[key_idx % len(key)]) - ord('A')
            plaintext.append(chr((ord(ch) - ord('a') - shift) % 26 + ord('a')))
            key_idx += 1
        else:
            plaintext.append(ch)
    return "".join(plaintext)

def solve():
    print("[*] Solving Vigenere...")
    cipher_file = Path(__file__).parent / "cipher.txt"
    if cipher_file.exists():
        ciphertext = cipher_file.read_text().strip()
    else:
        raise FileNotFoundError("cipher.txt not found")

    flag = decrypt_vigenere(ciphertext, "CYLAB")
    print(f"[+] Decrypted flag: {flag}")

    flag_file = Path(__file__).parent / "flag.txt"
    flag_file.write_text(flag + "\n")
    print(f"[+] Flag written to {flag_file}")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{D0NT_US3_V1G3N3R3_C1PH3R_4a372077}
```
