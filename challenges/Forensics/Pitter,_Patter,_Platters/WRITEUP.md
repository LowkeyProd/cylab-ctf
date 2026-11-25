# Writeup: Pitter, Patter, Platters

## Header & Metadata
- **Challenge:** Pitter, Patter, Platters (ID: 87)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** suspicious.dd.sda1
- **Official Flag:** `academy{b3_5t111_mL|_<3_d18a1e1e}`

---

## Mô tả bài toán (Overview / Analysis)
'Suspicious' is written all over this disk image. 

Download <a href='https://challenge-files.cylabacademy.net/library/aa2c48f05edb24ca322b4f28952e172d0b0540d7a55d14ebbbba84415951ec6e/suspicious.dd.sda1' download>suspicious.dd.sda1</a>


### Hints
- It may help to analyze this image in multiple ways: as a blob, and as an actual mounted disk.
- Have you heard of slack space? There is a certain set of tools that now come with Ubuntu that I'd recommend for examining that disk space phenomenon...

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
1. **Phân tích Disk Image & Slack Space**:
   - File ảnh `suspicious.dd.sda1` là một phân vùng Linux ext3 dung lượng ~31.3 MB (block size 1024 bytes).
   - Khi quét nội dung text trong image, ta phát hiện marker tại offset `0x200400` (block 2049):
     `Nothing to see here! But you may want to look here -->\n`
   - Phần dung lượng nằm giữa điểm kết thúc logic của file (EOF) và điểm kết thúc của physical block/cluster được gọi là **File Slack Space** (gồm RAM Slack và Drive Slack).

2. **Cơ chế ẩn giấu Flag trong Slack Space**:
   - Ngay sau ký tự newline `\n` của file văn bản tại offset `2098231` (`0x200437`), phần slack space chứa các byte dữ liệu ẩn giấu.
   - Trích xuất các byte tại vùng này:
     `7d 00 65 00 31 00 65 00 31 00 61 00 38 00 31 00 64 00 5f 00 33 00 3c 00 5f 00 7c 00 4c 00 6d 00 5f 00 31 00 31 00 74 00 35 00 5f 00 33 00 62 00 7b 00 79 00 6d 00 65 00 64 00 61 00 63 00 61`
   - Nhận thấy:
     - Ký tự đầu tiên là `}` (`0x7d`), các ký tự cuối là `y m e d a c a` (`academy` đảo ngược).
     - Xen kẽ giữa mỗi ký tự ASCII của flag là một byte null (`0x00`).

3. **Thuật toán khôi phục (Reconstruction Operator)**:
   - Áp dụng toán tử đảo ngược:
     1. **Lọc / Decimation**: Loại bỏ các byte null (`b != 0x00`).
     2. **Đảo chuỗi (String Reflection)**: Nghịch đảo thứ tự mảng ký tự (`[::-1]`).
   - Kết quả giải mã thu được chính xác flag: `academy{b3_5t111_mL|_<3_d18a1e1e}`.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Pitter, Patter, Platters (#87) - Automated Solver
Category: Forensics
Extracts the hidden flag from file slack space in an ext3 filesystem image.
"""

import os
import sys
import re

def parse_config(cfg_path: str) -> dict:
    """Dynamically parses connection configuration parameters."""
    config = {"HOST": "", "PORT": 0, "URL": ""}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    key = key.strip().upper()
                    val = val.strip()
                    if key == "PORT":
                        try:
                            config[key] = int(val)
                        except ValueError:
                            config[key] = 0
                    else:
                        config[key] = val
    return config

def inverse_transform(raw_slack: bytes) -> str:
    """
    Implements the inverse transformation operator (R o D_downarrow2):
    1. Decimates interleaved null padding bytes.
    2. Inverts the character sequence reflection.
    """
    # Step 1: Subsampling / decimation of null bytes
    decimated_chars = [chr(b) for b in raw_slack if b != 0]
    
    # Step 2: Reflection inversion (involution)
    reversed_candidate = "".join(decimated_chars)
    plaintext = reversed_candidate[::-1]
    return plaintext

def extract_closed_form(data: bytes, length: int = 33) -> str:
    """
    Closed-form coordinate extraction based on block 2049 RAM slack:
    f_i = data[2098295 - 2*i] for i in range(33)
    """
    base_offset = 2098295
    if len(data) > base_offset:
        chars = [chr(data[base_offset - 2 * i]) for i in range(length)]
        return "".join(chars)
    return ""

def solve():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    cfg_path = os.path.join(base_dir, "connection.cfg")
    config = parse_config(cfg_path)
    
    print(f"[*] Configuration loaded from {os.path.basename(cfg_path)}: {config}", flush=True)

    image_path = os.path.join(base_dir, "suspicious.dd.sda1")
    if not os.path.exists(image_path):
        print(f"[-] Error: Target image '{image_path}' not found.", flush=True)
        sys.exit(1)

    print(f"[*] Reading disk image: {os.path.basename(image_path)} ({os.path.getsize(image_path)} bytes)...", flush=True)
    with open(image_path, "rb") as f:
        data = f.read()

    # Method 1: Closed-form coordinate extraction
    closed_flag = extract_closed_form(data, length=33)
    print(f"[*] Closed-form candidate: {closed_flag}", flush=True)

    # Method 2: Dynamic slack space boundary detection
    marker = b"Nothing to see here! But you may want to look here -->\n"
    idx = data.find(marker)
    if idx == -1:
        # Fallback to prefix if newline variation occurs
        marker = b"Nothing to see here!"
        idx = data.find(marker)
        if idx == -1:
            print("[-] Error: Marker not found in disk image.", flush=True)
            sys.exit(1)

    print(f"[*] Identified logical file boundary marker at offset {idx} (0x{idx:x})", flush=True)
    
    # Search for slack opening delimiter '}'
    brace_idx = data.find(b"}", idx)
    if brace_idx == -1:
        print("[-] Error: Slack space terminator not found.", flush=True)
        sys.exit(1)

    print(f"[*] Slack space payload starts at offset {brace_idx} (0x{brace_idx:x})", flush=True)
    raw_slack = data[brace_idx:brace_idx + 128]
    dynamic_flag = inverse_transform(raw_slack)

    # Validate candidate flag format
    flag_pattern = re.compile(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})")
    match = flag_pattern.search(dynamic_flag) or flag_pattern.search(closed_flag)
    
    if not match:
        print("[-] Error: No valid flag pattern matching academy{...} or picoCTF{...} found.", flush=True)
        sys.exit(1)

    flag_token = match.group(1).strip()

    # Decoy and adversarial token filter
    decoys = ["decoy", "fake", "honeypot", "dummy", "not_the_flag"]
    if any(d in flag_token.lower() for d in decoys):
        print(f"[-] Error: Flag candidate '{flag_token}' matched decoy filter.", flush=True)
        sys.exit(1)

    print(f"[+] Successfully extracted and validated flag: {flag_token}", flush=True)

    # Persist flag to flag.txt
    flag_file = os.path.join(base_dir, "flag.txt")
    with open(flag_file, "w", encoding="utf-8") as f:
        f.write(flag_token + "\n")
    print(f"[+] Flag written to {os.path.basename(flag_file)}", flush=True)

    # Print flag token to standard output
    print(flag_token, flush=True)
    return flag_token

if __name__ == "__main__":
    solve()
```

---

## Log thực thi & Flag (Output & Verification)
```text
[*] Configuration loaded from connection.cfg: {'HOST': '', 'PORT': 0, 'URL': ''}
[*] Reading disk image: suspicious.dd.sda1 (32868864 bytes)...
[*] Closed-form candidate: academy{b3_5t111_mL|_<3_d18a1e1e}
[*] Identified logical file boundary marker at offset 2098176 (0x200400)
[*] Slack space payload starts at offset 2098231 (0x200437)
[+] Successfully extracted and validated flag: academy{b3_5t111_mL|_<3_d18a1e1e}
[+] Flag written to flag.txt
academy{b3_5t111_mL|_<3_d18a1e1e}
```
