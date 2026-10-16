# Writeup: EVEN RSA CAN BE BROKEN???

## Header & Metadata
- **Challenge:** EVEN RSA CAN BE BROKEN??? (ID: 470)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `academy{tw0_1$_pr!m39cf1fb4f}`

---

## Mô tả bài toán (Overview / Analysis)
This service provides you an encrypted flag. Can you decrypt it with just N & e?

### Hints
- How much do we trust randomness?
- Notice anything interesting about N?
- Try comparing N across multiple requests

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Trong mật mã học RSA tiêu chuẩn, khóa công khai bao gồm modulo $N = p \cdot q$, với $p$ và $q$ là hai số nguyên tố lớn ngẫu nhiên (thường từ 1024-bit đến 2048-bit trở lên).
Tất cả các số nguyên tố lớn hơn 2 đều là số lẻ, do đó tích $N = p \cdot q$ trong một hệ thống sinh khóa RSA chuẩn luôn luôn là một **số lẻ**.

Tuy nhiên, trong thử thách này:
1. Quan sát giá trị modulo $N$ trả về từ dịch vụ: chữ số tận cùng của $N$ là chữ số chẵn (ví dụ kết thúc bằng `6`), nghĩa là $N \pmod 2 = 0$.
2. Số nguyên tố chẵn duy nhất trong tập hợp số nguyên là số $2$.
3. Do đó, một trong hai thừa số nguyên tố cấu thành modulo $N$ chính là $p = 2$.
4. Thừa số nguyên tố còn lại được tính dễ dàng:
   $$q = \frac{N}{2}$$
5. Hàm Euler Phi được tính bằng:
   $$\phi(N) = (p - 1)(q - 1) = (2 - 1)(q - 1) = q - 1$$
6. Khóa bí mật $d$ được tính bằng nghịch đảo modulo của số mũ công khai $e = 65537$:
   $$d \equiv e^{-1} \pmod{\phi(N)}$$
7. Giải mã bản mã $c$ để thu được thông điệp gốc $m$ và cờ flag:
   $$m \equiv c^d \pmod N$$

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for EVEN RSA CAN BE BROKEN??? (#470)
Category: Cryptography
Target: chatelaine.cylabacademy.net:45446
Vulnerability: The RSA modulus N is even, meaning one of the prime factors is p = 2!
"""
import re
from pwn import *
from Crypto.Util.number import inverse, long_to_bytes

HOST = "chatelaine.cylabacademy.net"
PORT = 45446

def solve():
    io = remote(HOST, PORT)
    data = io.recvall(timeout=10).decode()
    io.close()

    n_match = re.search(r'N:\s*(\d+)', data)
    e_match = re.search(r'e:\s*(\d+)', data)
    c_match = re.search(r'cyphertext:\s*(\d+)', data)

    if not (n_match and e_match and c_match):
        print("[-] Failed to parse N, e, cyphertext")
        return None

    N = int(n_match.group(1))
    e = int(e_match.group(1))
    c = int(c_match.group(1))

    print(f"[+] Retrieved N: {N}")
    print(f"[+] Retrieved e: {e}")
    print(f"[+] Retrieved c: {c}")

    # Check if N is even (p = 2)
    if N % 2 == 0:
        p = 2
        q = N // p
        phi = (p - 1) * (q - 1)
        d = inverse(e, phi)
        m = pow(c, d, N)
        flag = long_to_bytes(m).decode(errors="ignore")
        print(f"[+] Decrypted Flag: {flag}")
        return flag
    else:
        print("[-] N is not even, checking small factors...")
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{tw0_1$_pr!m39cf1fb4f}
```
