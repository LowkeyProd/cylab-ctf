# Writeup: m00nwalk2 (#28)

## 1. Header & Metadata
- **Challenge Name:** m00nwalk2
- **Challenge ID:** 28
- **Category:** Forensics
- **Difficulty:** Hard
- **CTF Event:** CyLab Academy / picoCTF
- **Official Flag:** `academy{the_answer_lies_hidden_in_plain_sight}`

---

## 2. Overview / Analysis
Bài toán cung cấp 4 file âm thanh định dạng WAV:
- `message.wav`
- `clue1.wav`
- `clue2.wav`
- `clue3.wav`

Tương tự challenge `m00nwalk` trước đó (Apollo 11 SSTV transmission), các file này mang tín hiệu âm thanh Slow-Scan Television (SSTV) thường dùng trong liên lạc vô tuyến truyền hình ảnh.

---

## 3. Technical Deep-Dive
1. **Giải mã tín hiệu SSTV (Audio to Image):**
   Sử dụng công cụ `sstv` (Python SSTV decoder) để giải mã các file clue:
   ```bash
   sstv -d clue1.wav -o clue1.png
   ```
   Ảnh `clue1.png` hiển thị rõ dòng chữ:
   > **Password hidden_stegosaurus**

2. **Trích xuất Steghide Payload:**
   Với mật khẩu tìm được (`hidden_stegosaurus`), file `message.wav` chứa payload được giấu bằng thuật toán Steghide.
   Thực thi lệnh trích xuất:
   ```bash
   docker run --rm -v $(pwd):/work -w /work local/steghide extract -sf message.wav -p hidden_stegosaurus -xf -
   ```
   Kết quả trả về trực tiếp flag: `academy{the_answer_lies_hidden_in_plain_sight}`.

---

## 4. Solve Script (`solve.py`)
```python
#!/usr/bin/env python3
"""
Automated Solver for m00nwalk2 (#28)
Extracts flag from message.wav using Steghide with password recovered from clue1.wav SSTV.
"""
import subprocess
import re
from pathlib import Path

def solve():
    base_dir = Path(__file__).resolve().parent
    message_file = base_dir / "message.wav"
    password = "hidden_stegosaurus"

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{base_dir}:/work",
        "-w", "/work",
        "local/steghide",
        "extract", "-sf", "message.wav", "-p", password, "-xf", "-"
    ]
    res = subprocess.run(cmd, capture_output=True, check=True)
    out = res.stdout.decode("latin1", errors="ignore")
    
    m = re.search(r'(academy\{[^\}]+\}|picoCTF\{[^\}]+\})', out)
    if not m:
        raise ValueError(f"Flag not found in output: {out}")
        
    flag = m.group(1)
    print(f"[+] Recovered Flag: {flag}")
    
    flag_file = base_dir / "flag.txt"
    flag_file.write_text(flag + "\n")
    return flag

if __name__ == "__main__":
    solve()
```

---

## 5. Output & Verification
```bash
$ python3 solve.py
[+] Recovered Flag: academy{the_answer_lies_hidden_in_plain_sight}
```
- **Flag chính thức:** `academy{the_answer_lies_hidden_in_plain_sight}`
