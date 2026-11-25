# Writeup: Nice netcat...

## Header & Metadata
- **Challenge:** Nice netcat... (ID: 156)
- **CTF Event / Platform:** CyLab Security Academy / picoCTF
- **Category:** General Skills
- **Server / Instance:** `chatelaine.cylabacademy.net:21524`
- **Attached Files:** None
- **Official Flag:** `academy{g00d_k1tty!_n1c3_k1tty!_f6739}`

---

## Mô tả bài toán (Overview / Analysis)
Bài toán cung cấp một dịch vụ mạng qua lệnh `nc` trả về các giá trị số nguyên theo từng dòng (ASCII code).
Yêu cầu kết nối đến dịch vụ, nhận các số ASCII, chuyển đổi thành các ký tự tương ứng và thu thập chuỗi flag.

### Hints
- Sử dụng netcat để giao tiếp qua mạng TCP.
- Các số nhận được là mã thập phân ASCII của từng ký tự trong cờ.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
1. Kết nối TCP tới host và port được cấu hình trong `connection.cfg`.
2. Đọc toàn bộ dữ liệu phản hồi từ server.
3. Tách các token số và giải mã từng số $N$ thành ký tự bằng hàm `chr(int(N))`.
4. Trích xuất cờ theo định dạng `academy{...}` hoặc `picoCTF{...}` và lưu vào `flag.txt`.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
import socket
import re
import os

def get_connection_info():
    host = "chatelaine.cylabacademy.net"
    port = 21524
    cfg_path = os.path.join(os.path.dirname(__file__), "connection.cfg")
    if os.path.exists(cfg_path):
        with open(cfg_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("HOST="):
                    host = line.split("=", 1)[1].strip()
                elif line.startswith("PORT="):
                    port = int(line.split("=", 1)[1].strip())
    return host, port

def solve():
    host, port = get_connection_info()
    print(f"Connecting to {host}:{port}...", flush=True)
    
    data = b""
    with socket.create_connection((host, port), timeout=15) as s:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            
    raw_text = data.decode("utf-8", errors="ignore")
    print(f"Received raw data:\n{raw_text}", flush=True)
    
    numbers = raw_text.split()
    chars = [chr(int(n)) for n in numbers if n.isdigit()]
    decoded = "".join(chars)
    print(f"Decoded message: {decoded}", flush=True)
    
    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", decoded)
    if not match:
        raise ValueError(f"Flag pattern not found in decoded text: {decoded}")
        
    flag = match.group(1).strip()
    
    decoys = ["decoy", "fake", "honeypot", "dummy"]
    if any(d in flag.lower() for d in decoys):
        raise ValueError(f"Flag rejected as decoy: {flag}")
        
    print(f"Found flag: {flag}", flush=True)
    
    flag_path = os.path.join(os.path.dirname(__file__), "flag.txt")
    with open(flag_path, "w") as f:
        f.write(flag + "\n")
        
    print(f"Flag saved to {flag_path}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
```

---

## Log thực thi & Flag (Output & Verification)
```text
Connecting to chatelaine.cylabacademy.net:21524...
Received raw data:
97 
99 
97 
100 
101 
109 
121 
123 
103 
48 
48 
100 
95 
107 
49 
116 
116 
121 
33 
95 
110 
49 
99 
51 
95 
107 
49 
116 
116 
121 
33 
95 
102 
54 
55 
51 
57 
125 
10 

Decoded message: academy{g00d_k1tty!_n1c3_k1tty!_f6739}

Found flag: academy{g00d_k1tty!_n1c3_k1tty!_f6739}
Flag saved to C:\Users\lowkeyprod\cylab-ctf\challenges\General_Skills\Nice_netcat\flag.txt
```
