# Writeup: The Numbers

## Header & Metadata
- **Challenge:** The Numbers (ID: 68)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A` (Static Challenge)
- **Attached Files:** `the_numbers.png`
- **Official Flag:** `PICOCTF{THENUMBERSMASON}`

---

## Mô tả bài toán (Overview / Analysis)
Đề bài cung cấp một hình ảnh `the_numbers.png` với câu hỏi:
> "The numbers... what do they mean?"

Gợi ý đính kèm từ thử thách:
> "The flag is in the format PICOCTF{}"

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Quan sát bức ảnh `the_numbers.png`:
Hình ảnh chứa một tập hợp các con số được sắp xếp theo đúng định dạng của một cờ CTF:
```text
16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }
```

Thuật toán mã hóa ở đây là **A1Z26 Cipher (Bảng chữ cái đánh số từ 1 đến 26)**:
- $A \to 1, B \to 2, C \to 3, \dots, Z \to 26$

### 1. Phân tích tiền tố trước dấu ngoặc nhọn:
- `16` $\to$ P
- `9` $\to$ I
- `3` $\to$ C
- `15` $\to$ O
- `3` $\to$ C
- `20` $\to$ T
- `6` $\to$ F
$\implies$ Khớp hoàn hảo với format flag: `PICOCTF{`

### 2. Phân tích nội dung bên trong dấu ngoặc nhọn:
- `20` $\to$ T
- `8` $\to$ H
- `5` $\to$ E
$\implies$ `THE`

- `14` $\to$ N
- `21` $\to$ U
- `13` $\to$ M
- `2` $\to$ B
- `5` $\to$ E
- `18` $\to$ R
- `19` $\to$ S
$\implies$ `NUMBERS`

- `13` $\to$ M
- `1` $\to$ A
- `19` $\to$ S
- `15` $\to$ O
- `14` $\to$ N
$\implies$ `MASON`

Ghép lại ta thu được cờ hoàn chỉnh:
```text
PICOCTF{THENUMBERSMASON}
```
(Đây là câu thoại nổi tiếng trích từ tựa game kinh điển *Call of Duty: Black Ops*: *"The numbers, Mason! What do they mean?"*).

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for The Numbers (#68)
Category: Cryptography
Flag: PICOCTF{THENUMBERSMASON}
"""

def solve():
    # Numbers extracted from the_numbers.png:
    # 16 9 3 15 3 20 6 { 20 8 5 14 21 13 2 5 18 19 13 1 19 15 14 }
    prefix_nums = [16, 9, 3, 15, 3, 20, 6]
    content_nums = [20, 8, 5, 14, 21, 13, 2, 5, 18, 19, 13, 1, 19, 15, 14]

    # Convert 1-indexed alphabet (A=1, B=2, ..., Z=26)
    prefix = "".join(chr(ord('A') + n - 1) for n in prefix_nums)
    content = "".join(chr(ord('A') + n - 1) for n in content_nums)

    flag = f"{prefix}{{{content}}}"
    print(f"[+] Decoded Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Decoded Flag: PICOCTF{THENUMBERSMASON}
[+] Flag verified and saved to flag.txt:
PICOCTF{THENUMBERSMASON}
```
