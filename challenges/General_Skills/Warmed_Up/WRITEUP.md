# Warmed Up - Writeup

## 1. Header & Metadata
- **Challenge Name:** Warmed Up
- **CTF Event:** CyLab CTF / Cyber Academy (ID: 58)
- **Category:** General Skills
- **Difficulty:** Easy
- **Points:** 50
- **Target / Connection:** N/A (Static Challenge)
- **Official Flag:** `academy{61}`

---

## 2. Mô tả bài toán (Overview / Analysis)
Thử thách yêu cầu chuyển đổi giá trị cơ số 16 (hexadecimal) sang cơ số 10 (decimal):
> "What is 0x3D (base 16) in decimal (base 10)?"

Gợi ý từ đề bài:
> "Submit your answer in our flag format. For example, if your answer was '22', you would submit 'academy{22}' as the flag."

---

## 3. Chi tiết kỹ thuật (Technical Deep-Dive)
Trong hệ thống số thập lục phân (hexadecimal - base 16):
- Ký tự `3` đại diện cho giá trị $3$.
- Ký tự `D` đại diện cho giá trị $13$ (với $A=10, B=11, C=12, D=13, E=14, F=15$).

Biểu diễn toán học theo trọng số lũy thừa của 16:
$$\text{0x3D} = 3 \times 16^1 + 13 \times 16^0 = 48 + 13 = 61$$

Trong Python:
- `int("0x3D", 16)` hoặc `int("3D", 16)` cho kết quả `61`.

Định dạng flag của hệ thống yêu cầu bọc kết quả trong `academy{...}`, do đó flag cuối cùng là `academy{61}`.

---

## 4. Mã nguồn giải (Solve Script)
File: [`solve.py`](file:///Users/lowkeyprod/Documents/USTH/CTF/cylab/challenges/General_Skills/Warmed_Up/solve.py)

```python
#!/usr/bin/env python3
"""
Clean, self-contained solver for Warmed Up (#58)
Category: General Skills
Description: Converts 0x3D (base 16) to decimal (base 10) and formats flag.
"""
from pathlib import Path


def load_config():
    """Dynamically load connection parameters from connection.cfg if available."""
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    if cfg_file.exists():
        with open(cfg_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    return config


def hex_to_decimal(hex_str: str) -> int:
    """
    Mathematical transformation from base-16 to base-10 using positional expansion:
    N = sum(d_i * 16^i) for d_i in hex_str digits.
    """
    cleaned = hex_str.lower().removeprefix("0x")
    decimal_value = 0
    for char in cleaned:
        digit = int(char, 16)
        decimal_value = decimal_value * 16 + digit  # Horner's method
    return decimal_value


def solve():
    _ = load_config()

    # Mathematical transformation based on analysis.md
    hex_input = "0x3D"
    decimal_result = hex_to_decimal(hex_input)

    # Format flag
    flag = f"academy{{{decimal_result}}}"

    # Persist flag
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag.strip() + "\n", encoding="utf-8")

    # Output exact decoded token cleanly
    print(flag)
    return flag


if __name__ == "__main__":
    solve()
```

---

## 5. Log thực thi & Flag (Output & Verification)
```bash
$ python3 solve.py
academy{61}

$ cat flag.txt
academy{61}
```
