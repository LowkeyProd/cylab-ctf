# Writeup: waves over lambda

## Header & Metadata
- **Challenge:** waves over lambda (ID: 38)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `chatelaine.cylabacademy.net:12824`
- **Attached Files:** None
- **Official Flag:** `frequency_is_c_over_lambda_rhvrfbtyhv`

---

## Mô tả bài toán (Overview / Analysis)
We made a lot of substitutions to encrypt this. Can you decrypt it?
Connect with `nc chatelaine.cylabacademy.net 12824`.

### Hints
- Flag is not in the usual flag format

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Khi kết nối tới cổng dịch vụ TCP, server trả về một đoạn văn bản (được trích từ tác phẩm văn học cổ điển như *Heart of Darkness*) được mã hóa bằng thuật toán thay thế đơn bảng chữ cái ngẫu nhiên (monoalphabetic substitution cipher).

Ở đầu đoạn phản hồi, server luôn trả về một banner theo mẫu cố định:
```text
-------------------------------------------------------------------------------
<congrats> <here> <is> <your> <flag> - <frequency>_<is>_<c>_<over>_<lambda>_<suffix>
-------------------------------------------------------------------------------
```

Nhờ mẫu bản rõ đã biết (known plaintext) này:
- `congrats` (8 chữ cái)
- `here` (4 chữ cái)
- `is` (2 chữ cái)
- `your` (4 chữ cái)
- `flag` (4 chữ cái)
- `frequency` (9 chữ cái)
- `is` (2 chữ cái)
- `c` (1 chữ cái)
- `over` (4 chữ cái)
- `lambda` (6 chữ cái)

Tập hợp các ký tự trong mẫu trên cung cấp trực tiếp 20 ánh xạ chữ cái (gồm `a, b, c, d, e, f, g, h, i, l, m, n, o, q, r, s, t, u, v, y`). Phần đuôi ngẫu nhiên 10 ký tự của cờ chỉ bao gồm các ký tự nằm trong tập hợp các chữ cái này, cho phép giải mã chính xác 100% phần đuôi mà không cần phân tích tần suất trên phần còn lại của văn bản.

Kết quả giải mã phần đuôi: `rhvrfbtyhv`.
Định dạng cờ hoàn chỉnh: `frequency_is_c_over_lambda_rhvrfbtyhv`.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for waves over lambda (#38)
"""
import re
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "chatelaine.cylabacademy.net", 12824
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
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
    s.settimeout(10)
    s.connect((host, port))
    
    data = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"---" in data and data.count(b"---") >= 2:
                break
        except Exception:
            break
    s.close()
    
    text = data.decode("utf-8", errors="ignore")
    lines = [line.strip() for line in text.splitlines() if line.strip() and not set(line.strip()).issubset({'-', '='})]
    if not lines:
        raise ValueError("Could not find message lines")
    
    header = lines[0]
    match = re.search(r'([a-z]+)\s+([a-z]+)\s+([a-z]+)\s+([a-z]+)\s+([a-z]+)\s*-\s*([a-z]+)_([a-z]+)_([a-z]+)_([a-z]+)_([a-z]+)_([a-z]+)', header)
    if not match:
        raise ValueError(f"Header pattern mismatch: {header}")
    
    c_congrats, c_here, c_is, c_your, c_flag, c_freq, c_is2, c_c, c_over, c_lambda, c_suffix = match.groups()
    
    mapping = {}
    def learn(cipher_word, plain_word):
        for c, p in zip(cipher_word, plain_word):
            mapping[c] = p
            
    learn(c_congrats, "congrats")
    learn(c_here, "here")
    learn(c_is, "is")
    learn(c_your, "your")
    learn(c_flag, "flag")
    learn(c_freq, "frequency")
    learn(c_is2, "is")
    learn(c_c, "c")
    learn(c_over, "over")
    learn(c_lambda, "lambda")
    
    decrypted_suffix = "".join(mapping.get(c, "?") for c in c_suffix)
    flag = f"frequency_is_c_over_lambda_{decrypted_suffix}"
    print(f"[+] Flag found: {flag}", flush=True)
    
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag)
    print(f"[+] Saved flag to {flag_file}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
```

---

## Log thực thi & Flag (Output & Verification)
```text
[*] Connecting to chatelaine.cylabacademy.net:12824...
[*] Received server message:
-------------------------------------------------------------------------------
wudmxpjb enxn hb kucx lrpm - lxngcndwk_hb_w_uinx_rpzoyp_xeixlojkei
-------------------------------------------------------------------------------
...
[*] Analyzing header: wudmxpjb enxn hb kucx lrpm - lxngcndwk_hb_w_uinx_rpzoyp_xeixlojkei
[*] Recovered partial alphabet substitution (20 letters)
[+] Flag found: frequency_is_c_over_lambda_rhvrfbtyhv
[+] Saved flag to C:\Users\lowkeyprod\cylab-ctf\challenges\Cryptography\waves_over_lambda\flag.txt
```
