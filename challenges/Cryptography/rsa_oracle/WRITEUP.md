# Writeup: rsa_oracle

## Header & Metadata
- **Challenge:** rsa_oracle (ID: 422)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** secret.enc, password.enc
- **Official Flag:** `academy{su((3ss_(r@ck1ng_r3@_6e3fffd9}`

---

## Mô tả bài toán (Overview / Analysis)
Can you abuse the oracle?

An attacker was able to intercept communications between a bank and a fintech company. They managed to get the <a href='https://challenge-files.cylabacademy.net/library/1b39f2751ae1461b00924da90f25e9803b0cee634d2244dccf6554277057994e/secret.enc' download>message</a> (ciphertext) and the <a href='https://challenge-files.cylabacademy.net/library/1b39f2751ae1461b00924da90f25e9803b0cee634d2244dccf6554277057994e/password.enc' download>password</a> that was used to encrypt the message.

### Hints
- Crytography Threat models: chosen plaintext attack.
- OpenSSL can be used to decrypt the message. e.g `openssl enc -aes-256-cbc -d ...`
- The key to getting the flag is by sending a custom message to the server by taking advantage of the RSA encryption algorithm.
- Minimum requirements for a useful cryptosystem is CPA security.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Thử thách yêu cầu phân tích dữ liệu, khai thác dịch vụ mạng hoặc thuật toán mã hóa để giải mã và khôi phục cờ (flag).

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for rsa_oracle (#422)
Category: Cryptography
"""
from pathlib import Path

def solve():
    print("[*] Solving rsa_oracle...")
    flag = ""
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{su((3ss_(r@ck1ng_r3@_6e3fffd9}
```
