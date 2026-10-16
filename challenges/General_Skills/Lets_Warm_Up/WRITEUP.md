# Lets Warm Up - Writeup

## 1. Header & Metadata
- **Challenge Name:** Lets Warm Up
- **CTF Event:** CyLab CTF / Cyber Academy
- **Category:** General Skills
- **Difficulty:** Easy
- **Points:** 50
- **Target / Connection:** N/A (Static Challenge)
- **Official Flag:** `academy{p}`

---

## 2. Mô tả bài toán (Overview / Analysis)
Thử thách đưa ra câu hỏi cơ bản về bảng mã ký tự và hệ đếm:
> "If I told you a word started with `0x70` in hexadecimal, what would it start with in ASCII?"

Gợi ý từ đề bài:
> "Submit your answer in our flag format. For example, if your answer was 'hello', you would submit 'academy{hello}' as the flag."

Yêu cầu chuyển đổi giá trị số nguyên biểu diễn dưới dạng cơ số 16 (hexadecimal) `0x70` sang ký tự biểu diễn tương ứng trong bảng mã chuẩn ASCII (American Standard Code for Information Interchange).

---

## 3. Chi tiết kỹ thuật (Technical Deep-Dive)
Trong biểu diễn cơ số 16:
$$\text{0x70} = 7 \times 16^1 + 0 \times 16^0 = 112 \ (\text{cơ số 10})$$

Đối chiếu bảng mã ASCII:
- Mã thập phân `112` (hoặc mã hex `0x70`) tương ứng với ký tự chữ thường `'p'`.
- Trong Python: `chr(0x70)` trả về `'p'`.

Định dạng flag của hệ thống là `academy{...}`, do đó flag hoàn chỉnh là `academy{p}`.

---

## 4. Mã nguồn giải (Solve Script)
File: [`solve.py`](file:///Users/lowkeyprod/Documents/USTH/CTF/cylab/challenges/General_Skills/Lets_Warm_Up/solve.py)

```python
#!/usr/bin/env python3
"""
Solve script for Lets Warm Up (#22)
Category: General Skills
"""
from pathlib import Path

def parse_connection_cfg(cfg_path: Path):
    config = {}
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    return config

def solve():
    base_dir = Path(__file__).resolve().parent
    parse_connection_cfg(base_dir / "connection.cfg")

    # 0x70 in hex -> ASCII char
    hex_val = 0x70
    ascii_char = chr(hex_val)

    flag = f"academy{{{ascii_char}}}"
    flag_path = base_dir / "flag.txt"
    flag_path.write_text(flag.strip() + "\n", encoding="utf-8")

    print(flag)
    return flag

if __name__ == "__main__":
    solve()
```

---

## 5. Log thực thi & Flag (Output & Verification)
```bash
$ python3 solve.py
academy{p}

$ cat flag.txt
academy{p}
```
