# Writeup: Play Nice

## Header & Metadata
- **Challenge:** Play Nice (ID: 114)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `7a63caadf145ca5024f2878d534eec0f`

---

## Mô tả bài toán (Overview / Analysis)
Not all ancient ciphers were so bad... The flag is not in standard format.

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Thử thách yêu cầu phân tích dữ liệu, khai thác dịch vụ mạng hoặc thuật toán mã hóa để giải mã và khôi phục cờ (flag).

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Play Nice (#114)
Target: chatelaine.cylabacademy.net:22515
"""
import re
import socket
from pathlib import Path

SQUARE_SIZE = 6

def generate_square(alphabet):
    assert len(alphabet) == pow(SQUARE_SIZE, 2)
    matrix = []
    for i, letter in enumerate(alphabet):
        if i % SQUARE_SIZE == 0:
            row = []
        row.append(letter)
        if i % SQUARE_SIZE == (SQUARE_SIZE - 1):
            matrix.append(row)
    return matrix

def get_index(letter, matrix):
    for row in range(SQUARE_SIZE):
        for col in range(SQUARE_SIZE):
            if matrix[row][col] == letter:
                return (row, col)
    raise ValueError(f"letter {letter} not found in matrix")

def decrypt_pair(pair, matrix):
    p1 = get_index(pair[0], matrix)
    p2 = get_index(pair[1], matrix)

    if p1[0] == p2[0]:
        return matrix[p1[0]][(p1[1] - 1) % SQUARE_SIZE] + matrix[p2[0]][(p2[1] - 1) % SQUARE_SIZE]
    elif p1[1] == p2[1]:
        return matrix[(p1[0] - 1) % SQUARE_SIZE][p1[1]] + matrix[(p2[0] - 1) % SQUARE_SIZE][p2[1]]
    else:
        return matrix[p1[0]][p2[1]] + matrix[p2[0]][p1[1]]

def decrypt_string(s, matrix):
    result = ""
    for i in range(0, len(s), 2):
        result += decrypt_pair(s[i:i + 2], matrix)
    return result

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 22515
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("HOST=") and line.split("=", 1)[1]:
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def solve():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    buf = ""
    while "What is the plaintext message?" not in buf:
        chunk = s.recv(4096).decode('utf-8')
        if not chunk:
            break
        buf += chunk
    
    print("[*] Received server prompt:\n", buf, flush=True)
    
    # Parse alphabet and encrypted message
    # Here is the alphabet: 0123456789abcdefghijklmnopqrstuvwxyz
    # Here is the encrypted message: ...
    m_alpha = re.search(r"Here is the alphabet:\s*([^\r\n]+)", buf)
    m_enc = re.search(r"Here is the encrypted message:\s*([^\r\n]+)", buf)
    
    if not m_alpha or not m_enc:
        print("[-] Failed to parse alphabet or encrypted message!", flush=True)
        return
        
    alphabet = m_alpha.group(1).strip()
    enc_msg = m_enc.group(1).strip()
    
    print(f"[*] Alphabet: {alphabet} (len {len(alphabet)})", flush=True)
    print(f"[*] Encrypted: {enc_msg}", flush=True)
    
    matrix = generate_square(alphabet)
    dec_msg = decrypt_string(enc_msg, matrix)
    print(f"[*] Decrypted plaintext: {dec_msg}", flush=True)
    
    s.sendall((dec_msg + "\n").encode('utf-8'))
    
    response = ""
    while True:
        chunk = s.recv(4096).decode('utf-8')
        if not chunk:
            break
        response += chunk
        if "Congratulations!" in response or "{" in response:
            break
            
    print("[*] Server response:\n", response, flush=True)
    s.close()
    
    # Look for flag in response
    flag_match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", response)
    if flag_match:
        flag = flag_match.group(1)
    else:
        # Check "Here's the flag: <flag>"
        flag_match2 = re.search(r"Here's the flag:\s*([^\r\n]+)", response)
        if flag_match2:
            flag = flag_match2.group(1).strip()
        else:
            flag = response.strip()
            
    print(f"[+] Flag found: {flag}", flush=True)
    Path("flag.txt").write_text(flag)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
7a63caadf145ca5024f2878d534eec0f
```
