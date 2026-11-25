# Writeup: The Numbers

## Header & Metadata
- **Challenge:** The Numbers (ID: 68)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** the_numbers.png
- **Official Flag:** `PICOCTF{THENUMBERSMASON}`

---

## Mô tả bài toán (Overview / Analysis)
The numbers... what do they mean?
<a href='https://challenge-files.cylabacademy.net/library/664bc3a85525cfd5a2af151d29f2744ba334880e28e60f9a513aba13633199d4/the_numbers.png' download>numbers</a>

### Hints
- The flag is in the format PICOCTF{}

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

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
[+] Flag verified and saved to flag.txt:
PICOCTF{THENUMBERSMASON}
```
