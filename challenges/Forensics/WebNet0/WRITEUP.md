# Writeup: WebNet0

## Header & Metadata
- **Challenge Name:** WebNet0 (ID: 32)
- **CTF Event:** CyLab Academy CTF
- **Category:** Forensics
- **Difficulty:** Hard (350 points)
- **Attached Files:** `webnet0-capture.pcap`, `picopico.key`
- **Target / Server:** Local files (`connection.cfg` specifies `challenge-files.cylabacademy.net:443`)
- **Official Flag:** `academy{nongshim.shrimp.crackers}`

---

## Mô tả bài toán (Overview / Analysis)
Đề bài cung cấp hai tệp:
1. `webnet0-capture.pcap`: Tệp bắt gói tin mạng pcap ghi lại lưu lượng truy cập mạng.
2. `picopico.key`: Khóa bí mật RSA (`-----BEGIN PRIVATE KEY-----`).

Yêu cầu bài toán là phân tích lưu lượng bắt được trong file PCAP kết hợp với khóa bí mật để giải mã các gói tin được mã hóa và thu hồi flag.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)

### 1. Phân tích lưu lượng mạng (PCAP Analysis)
Kiểm tra các gói tin bằng công cụ `tshark`:
- Giao thức bắt được chủ yếu là TCP trên cổng 443 (HTTPS/TLS) giữa địa chỉ IP `128.237.140.23` và `172.31.22.220`.
- Kiểm tra các cipher suite được đàm phán trong quá trình TLS Handshake:
  ```bash
  tshark -r webnet0-capture.pcap -Y "tls.handshake.ciphersuite" -T fields -e tls.handshake.ciphersuite
  ```
  Cipher suite được Server lựa chọn là `0x009d`, tương ứng với `TLS_RSA_WITH_AES_256_GCM_SHA384`.

### 2. Nguyên lý giải mã TLS bằng RSA Private Key
- Do phiên làm việc sử dụng cơ chế trao đổi khóa RSA truyền thống (`TLS_RSA`), Client sinh ra pre-master secret và mã hóa nó trực tiếp bằng Public Key RSA của máy chủ (nằm trong chứng chỉ).
- Khi có Private Key của server (`picopico.key`), bất kỳ bộ giải mã TLS nào (như Wireshark hoặc `tshark`) đều có thể giải mã pre-master secret, từ đó suy diễn ra master secret và các session key (AES keys) để giải mã toàn bộ dữ liệu ứng dụng (Application Data / HTTP).

### 3. Cấu hình tshark và giải mã gói tin
Trong các phiên bản Wireshark / tshark hiện đại (Wireshark 3.x+ / 4.x+), cấu hình RSA private key được truyền qua bảng UAT `rsa_keys` bằng tham số:
```bash
-o 'uat:rsa_keys:"<path_to_key>",""'
```

Khi chạy giải mã và lọc các gói tin HTTP:
```bash
tshark -r webnet0-capture.pcap -o "uat:rsa_keys:\"picopico.key\",\"\"" -Y "http" -V
```

Tại Frame số 32 và 35 (các gói tin HTTP/1.1 200 OK trả về từ máy chủ web), máy chủ đính kèm một custom header chứa flag:
```http
HTTP/1.1 200 OK\r\n
Date: Fri, 23 Aug 2019 15:56:36 GMT\r\n
Server: Apache/2.4.29 (Ubuntu)\r\n
ETag: "5ff-58fee50dc3fb0-gzip"\r\n
Content-Encoding: gzip\r\n
Pico-Flag: academy{nongshim.shrimp.crackers}\r\n
Content-Length: 821\r\n
...
```

Header `Pico-Flag` chứa flag: `academy{nongshim.shrimp.crackers}`.

---

## Mã nguồn khai thác (Solve Script / Exploit)
File [`solve.py`](file:///Users/lowkeyprod/Documents/USTH/CTF/cylab/challenges/Forensics/WebNet0/solve.py):

```python
#!/usr/bin/env python3
"""
WebNet0 Solve Script
Decrypts TLS traffic in a PCAP file using an RSA private key with tshark,
and extracts the flag from HTTP response headers.
"""

import os
import re
import shutil
import subprocess
import sys

PCAP_FILE = os.path.abspath("webnet0-capture.pcap")
KEY_FILE = os.path.abspath("picopico.key")
FLAG_FILE = "flag.txt"

def find_tshark():
    candidates = [
        shutil.which("tshark"),
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    raise FileNotFoundError("tshark binary not found. Please ensure Wireshark/tshark is installed.")

def solve():
    tshark_bin = find_tshark()
    print(f"[*] Using tshark at: {tshark_bin}")

    cmd = [
        tshark_bin,
        "-r", PCAP_FILE,
        "-o", f'uat:rsa_keys:"{KEY_FILE}",""',
        "-Y", "http",
        "-V"
    ]

    print("[*] Decrypting TLS packets and extracting HTTP layers...")
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", result.stdout)
    if not match:
        print("[-] Flag not found in decrypted traffic.")
        sys.exit(1)

    flag = match.group(1)
    print(f"[+] Found Flag: {flag}")

    with open(FLAG_FILE, "w") as f:
        f.write(flag + "\n")
    print(f"[+] Saved flag to {FLAG_FILE}")

    return flag

if __name__ == "__main__":
    solve()
```

---

## Log thực thi & Flag (Output & Verification)

```console
$ python3 solve.py
[*] Using tshark at: /Applications/Wireshark.app/Contents/MacOS/tshark
[*] Decrypting TLS packets and extracting HTTP layers...
[+] Found Flag: academy{nongshim.shrimp.crackers}
[+] Saved flag to flag.txt

$ cat flag.txt
academy{nongshim.shrimp.crackers}
```
