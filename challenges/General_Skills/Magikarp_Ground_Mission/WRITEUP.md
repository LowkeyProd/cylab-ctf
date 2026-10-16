# Magikarp Ground Mission - Writeup

## 1. Header & Metadata
- **Challenge Name:** Magikarp Ground Mission
- **Event:** Cylab Academy / picoCTF
- **Category:** General Skills
- **Difficulty:** Easy
- **Points:** 30
- **Host / Target:** `chatelaine.cylabacademy.net:37440` (SSH, user `ctf-player`)
- **Official Flag:** `academy{xxsh_0ut_0f_//4t3r_47c47679}`

---

## 2. Mô tả bài toán (Overview & Analysis)
Đề bài cung cấp tài khoản SSH vào một môi trường Linux container nhằm kiểm tra kỹ năng điều hướng cơ bản trong shell Linux (`cd`, `ls`, `cat`):
- SSH vào máy chủ mục tiêu với thông tin tài khoản được cấp.
- Lần theo các chỉ dẫn và file flag phân mảnh nằm rải rác trên hệ thống tập tin Linux.

---

## 3. Chi tiết kỹ thuật (Technical Deep-Dive)
Sau khi kết nối SSH vào hệ thống:
1. Thư mục ban đầu của người dùng `/home/ctf-player` chứa:
   - Thư mục con `drop-in/`
   - File `3of3.flag.txt`
2. Di chuyển vào `drop-in/`:
   - `1of3.flag.txt`: Chứa phần đầu của flag: `academy{xxsh_`
   - `instructions-to-2of3.txt`: Hướng dẫn đến thư mục gốc `/` (`Next, go to the root of all things, more succinctly '/'`).
3. Di chuyển đến `/`:
   - `2of3.flag.txt`: Chứa phần thứ hai của flag: `0ut_0f_//4t3r_`
   - `instructions-to-3of3.txt`: Hướng dẫn quay về thư mục nhà `~` (`/home/ctf-player`).
4. Tại `/home/ctf-player`:
   - `3of3.flag.txt`: Chứa phần kết thúc của flag: `47c47679}`
5. Ghép nối cả 3 phần:
   $$\text{Part 1} + \text{Part 2} + \text{Part 3} = \text{academy\{xxsh\_} + \text{0ut\_0f\_//4t3r\_} + \text{47c47679\}} = \text{academy\{xxsh\_0ut\_0f\_//4t3r\_47c47679\}}$$

---

## 4. Mã nguồn khai thác (Solve Script)
Script `solve.py` tự động đọc thông số kết nối từ `connection.cfg`, thiết lập phiên SSH thông qua thư viện `paramiko`, đọc từng mảnh flag và kết hợp lại:

```python
#!/usr/bin/env python3
"""
Solve script for Magikarp Ground Mission (#189)
Category: General Skills
Domain Methodology: Computer Science & Algorithms (Easy)
"""
import os
import re
from pathlib import Path
import paramiko

def parse_config(cfg_path: Path):
    config = {}
    if not cfg_path.exists():
        return config
    with open(cfg_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                config[key.strip()] = val.strip()
    return config

def solve():
    script_dir = Path(__file__).resolve().parent
    cfg_path = script_dir / "connection.cfg"
    config = parse_config(cfg_path)

    host = config.get("HOST", "chatelaine.cylabacademy.net")
    port = int(config.get("PORT", 37440))
    username = config.get("USER", "ctf-player")
    password = config.get("PASS", "f6904eaa")

    print(f"[*] Connecting to {host}:{port} as {username}...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=username, password=password, timeout=15)

    flag_parts = {}

    # Read part 1
    _, stdout, _ = client.exec_command("cat /home/ctf-player/drop-in/1of3.flag.txt")
    part1 = stdout.read().decode("utf-8").strip()
    flag_parts[1] = part1
    print(f"[+] Part 1: {part1}")

    # Read part 2
    _, stdout, _ = client.exec_command("cat /2of3.flag.txt")
    part2 = stdout.read().decode("utf-8").strip()
    flag_parts[2] = part2
    print(f"[+] Part 2: {part2}")

    # Read part 3
    _, stdout, _ = client.exec_command("cat /home/ctf-player/3of3.flag.txt")
    part3 = stdout.read().decode("utf-8").strip()
    flag_parts[3] = part3
    print(f"[+] Part 3: {part3}")

    client.close()

    flag = f"{flag_parts[1]}{flag_parts[2]}{flag_parts[3]}"
    print(f"[+] Reconstructed Flag: {flag}")

    # Save to flag.txt
    flag_file = script_dir / "flag.txt"
    flag_file.write_text(flag + "\n", encoding="utf-8")
    print(f"[+] Flag saved to {flag_file}")

    return flag

if __name__ == "__main__":
    solve()
```

---

## 5. Log thực thi & Flag (Output & Verification)
```
$ python3 solve.py
[*] Connecting to chatelaine.cylabacademy.net:37440 as ctf-player...
[+] Part 1: academy{xxsh_
[+] Part 2: 0ut_0f_//4t3r_
[+] Part 3: 47c47679}
[+] Reconstructed Flag: academy{xxsh_0ut_0f_//4t3r_47c47679}
[+] Flag saved to /Users/lowkeyprod/Documents/USTH/CTF/cylab/challenges/General_Skills/Magikarp_Ground_Mission/flag.txt
```
