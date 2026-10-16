# Writeup - asm2

## 1. Header & Metadata
- **Challenge Name:** asm2
- **ID:** 16
- **Event:** Cylab CTF / picoCTF
- **Category:** Reverse Engineering
- **File đính kèm:** [test.S](file:///Users/lowkeyprod/Documents/USTH/CTF/cylab/challenges/Reverse_Engineering/asm2/test.S)
- **Flag chính thức:** `0x84`

---

## 2. Mô tả bài toán (Overview / Analysis)
Đề bài cung cấp một đoạn mã hợp ngữ x86 32-bit (`test.S`) chứa hàm `asm2` và yêu cầu xác định giá trị trả về của hàm khi gọi `asm2(0xb, 0x1a)`. Giá trị trả về phải được gửi dưới dạng số thập lục phân bắt đầu bằng tiền tố `0x`.

---

## 3. Chi tiết kỹ thuật (Technical Deep-Dive)

### 3.1. Phân tích mã Assembly

Dưới đây là nội dung của `test.S`:

```assembly
asm2:
	<+0>:	push   ebp
	<+1>:	mov    ebp,esp
	<+3>:	sub    esp,0x10
	<+6>:	mov    eax,DWORD PTR [ebp+0xc]
	<+9>:	mov    DWORD PTR [ebp-0x4],eax
	<+12>:	mov    eax,DWORD PTR [ebp+0x8]
	<+15>:	mov    DWORD PTR [ebp-0x8],eax
	<+18>:	jmp    0x119c <asm2+31>
	<+20>:	add    DWORD PTR [ebp-0x4],0x1
	<+24>:	add    DWORD PTR [ebp-0x8],0xe7
	<+31>:	cmp    DWORD PTR [ebp-0x8],0x5ed6
	<+38>:	jle    0x1191 <asm2+20>
	<+40>:	mov    eax,DWORD PTR [ebp-0x4]
	<+43>:	leave
	<+44>:	ret
```

### 3.2. Layout bộ nhớ và Calling Convention (cdecl 32-bit)
Khi hàm `asm2(0xb, 0x1a)` được gọi:
- `[ebp+0x8]` là tham số thứ nhất: `arg1 = 0xb` (11).
- `[ebp+0xc]` là tham số thứ hai: `arg2 = 0x1a` (26).
- Biến cục bộ `[ebp-0x4]` (`var_4`): khởi tạo bằng `arg2 = 0x1a`.
- Biến cục bộ `[ebp-0x8]` (`var_8`): khởi tạo bằng `arg1 = 0xb`.

### 3.3. Dòng điều khiển (Control Flow)
1. **Khởi tạo:**
   - `var_4 = 0x1a`
   - `var_8 = 0xb`
2. **Nhảy tới điều kiện lặp (`jmp <asm2+31>`):**
   - So sánh `var_8` với `0x5ed6` (`cmp DWORD PTR [ebp-0x8], 0x5ed6`).
   - Nếu `var_8 <= 0x5ed6` (`jle`), nhảy tới thân vòng lặp tại `<asm2+20>`.
3. **Thân vòng lặp:**
   - `var_4 += 0x1`
   - `var_8 += 0xe7`
4. **Kết thúc vòng lặp:**
   - Khi `var_8 > 0x5ed6`, hàm lấy `var_4` đưa vào thanh ghi `eax` và trả về (`ret`).

### 3.4. Tính toán số vòng lặp
- Giá trị ban đầu của `var_8`: $11$.
- Mỗi vòng lặp, `var_8` tăng thêm $0xe7 = 231$.
- Vòng lặp dừng khi $var\_8 > 0x5ed6 = 24278$.
- Điều kiện tiếp tục lặp tại đầu mỗi bước:
  $$11 + 231 \times k \le 24278 \implies 231 \times k \le 24267 \implies k \le 105.05$$
  Do $k$ đếm từ $0$ (lần kiểm tra đầu tiên), vòng lặp chạy đúng $106$ lần ($k = 0, 1, \dots, 105$).
- Tại lần lặp thứ 106 ($k = 105$):
  - `var_8` sau tăng = $11 + 106 \times 231 = 24497 > 24278$ (thoát vòng lặp).
  - `var_4` sau tăng = $26 + 106 = 132$.
- Chuyển sang hệ Hex: $132 = 0x84$.

---

## 4. Mã nguồn giải (Solve Script / Exploit)
File [`solve.py`](file:///Users/lowkeyprod/Documents/USTH/CTF/cylab/challenges/Reverse_Engineering/asm2/solve.py):

```python
#!/usr/bin/env python3
"""
Solver for asm2 (Reverse Engineering)
Simulates the execution of the assembly function asm2 from test.S.
"""

import os
import re
import json
from pathlib import Path


def parse_asm2_from_file(filepath: Path):
    """
    Parses test.S to extract constants used in asm2.
    """
    if not filepath.exists():
        # Fallback constants if test.S is missing
        return 0x1, 0xE7, 0x5ED6

    content = filepath.read_text(encoding="utf-8")

    inc_v4_match = re.search(
        r"add\s+DWORD PTR \[ebp-0x4\],\s*(0x[0-9a-fA-F]+|\d+)", content
    )
    inc_v8_match = re.search(
        r"add\s+DWORD PTR \[ebp-0x8\],\s*(0x[0-9a-fA-F]+|\d+)", content
    )
    cmp_v8_match = re.search(
        r"cmp\s+DWORD PTR \[ebp-0x8\],\s*(0x[0-9a-fA-F]+|\d+)", content
    )

    inc_v4 = int(inc_v4_match.group(1), 0) if inc_v4_match else 0x1
    inc_v8 = int(inc_v8_match.group(1), 0) if inc_v8_match else 0xE7
    cmp_v8 = int(cmp_v8_match.group(1), 0) if cmp_v8_match else 0x5ED6

    return inc_v4, inc_v8, cmp_v8


def get_call_args(base_dir: Path):
    """
    Extracts function arguments asm2(arg1, arg2) from info.json or README.md.
    Defaults to (0xb, 0x1a).
    """
    info_path = base_dir / "info.json"
    if info_path.exists():
        try:
            with open(info_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                desc = data.get("description", "")
                m = re.search(r"asm2\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)", desc)
                if m:
                    return int(m.group(1), 0), int(m.group(2), 0)
        except Exception:
            pass
    return 0xB, 0x1A


def simulate_asm2(arg1: int, arg2: int, inc_v4: int = 0x1, inc_v8: int = 0xE7, cmp_v8: int = 0x5ED6) -> int:
    """
    Simulates the assembly logic:
        <+0>: push ebp
        <+1>: mov ebp, esp
        <+3>: sub esp, 0x10
        <+6>: mov eax, DWORD PTR [ebp+0xc]   ; eax = arg2
        <+9>: mov DWORD PTR [ebp-0x4], eax   ; var_4 = arg2
        <+12>: mov eax, DWORD PTR [ebp+0x8]  ; eax = arg1
        <+15>: mov DWORD PTR [ebp-0x8], eax  ; var_8 = arg1
        <+18>: jmp <asm2+31>
        <+20>: add DWORD PTR [ebp-0x4], inc_v4
        <+24>: add DWORD PTR [ebp-0x8], inc_v8
        <+31>: cmp DWORD PTR [ebp-0x8], cmp_v8
        <+38>: jle <asm2+20>
        <+40>: mov eax, DWORD PTR [ebp-0x4]
        <+43>: leave
        <+44>: ret
    """
    var_4 = arg2 & 0xFFFFFFFF
    var_8 = arg1 & 0xFFFFFFFF

    # Jump to cmp first
    while var_8 <= cmp_v8:
        var_4 = (var_4 + inc_v4) & 0xFFFFFFFF
        var_8 = (var_8 + inc_v8) & 0xFFFFFFFF

    return var_4


def solve():
    script_dir = Path(__file__).parent.resolve()
    test_asm_file = script_dir / "test.S"

    # 1. Read input data
    inc_v4, inc_v8, cmp_v8 = parse_asm2_from_file(test_asm_file)
    arg1, arg2 = get_call_args(script_dir)

    # 2. Perform transformations / emulation
    result = simulate_asm2(arg1, arg2, inc_v4, inc_v8, cmp_v8)
    token = hex(result)

    # 3. Print decoded token
    print(token)

    # 4. Save flag.txt
    flag_file = script_dir / "flag.txt"
    with open(flag_file, "w", encoding="utf-8") as f:
        f.write(token.strip())

    return token


if __name__ == "__main__":
    solve()
```

---

## 5. Log thực thi & Flag (Output & Verification)

```bash
$ python3 solve.py
0x84

$ cat flag.txt
0x84
```

**Flag chính thức:** `0x84`
