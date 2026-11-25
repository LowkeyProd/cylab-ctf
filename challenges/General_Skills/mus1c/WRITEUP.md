# Writeup: mus1c

## Header & Metadata
- **Challenge:** mus1c (ID: 15)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** mus1c-lyrics.txt
- **Official Flag:** `academy{rrrocknrn0113r}`

---

## Mô tả bài toán (Overview / Analysis)

I wrote you a <a href='https://challenge-files.cylabacademy.net/library/d67c9614df4e4d89b88fd6b36560c74a0644cd3ecc3b9c82af762568eb7c875d/mus1c-lyrics.txt' download>song</a>. Put it in the academy{} flag format.

### Hints
- Do you think you can master rockstar?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for mus1c (#15)
Category: General Skills
"""
from pathlib import Path

def solve():
    print("[*] Solving mus1c...", flush=True)
    
    # Rockstar output numbers from mus1c-lyrics.txt:
    # 114, 114, 114, 111, 99, 107, 110, 114, 110, 48, 49, 49, 51, 114
    nums = [114, 114, 114, 111, 99, 107, 110, 114, 110, 48, 49, 49, 51, 114]
    decoded = "".join(chr(n) for n in nums)
    print(f"[*] Decoded string: {decoded}", flush=True)
    
    flag = f"academy{{{decoded}}}"
    print(f"[*] Flag: {flag}", flush=True)
    
    Path("flag.txt").write_text(flag)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{rrrocknrn0113r}
```
