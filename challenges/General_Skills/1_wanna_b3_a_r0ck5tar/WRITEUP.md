# Writeup: 1_wanna_b3_a_r0ck5tar

## Header & Metadata
- **Challenge:** 1_wanna_b3_a_r0ck5tar (ID: 82)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** r0ck5tar-lyrics.txt
- **Official Flag:** `academy{BONJOVI}`

---

## Mô tả bài toán (Overview / Analysis)

I wrote you another <a href='https://challenge-files.cylabacademy.net/library/1961679e482fd1537dc967de3770d328b08c5821425e25289559a3d5029fc4ef/r0ck5tar-lyrics.txt' download>song</a>. Put the flag in the academy{} flag format

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for 1_wanna_b3_a_r0ck5tar (#82)
Category: General Skills
"""
import re
from pathlib import Path

def solve():
    print("[*] Solving 1_wanna_b3_a_r0ck5tar...", flush=True)
    
    # Trace the output of the rockstar program
    # The output statements in the lyrics after inputs are:
    # 11: Tommy is rockin guitar           -> 66 ('B')
    # 12: Shout Tommy!                    -> prints 66
    # 13: Music is amazing sensation       -> 79 ('O')
    # 14: Jamming is awesome presence      -> 78 ('N')
    # 15: Scream Music!                   -> prints 79
    # 16: Scream Jamming!                 -> prints 78
    # 17: Tommy is playing rock           -> 74 ('J')
    # 18: Scream Tommy!                   -> prints 74
    # 19: They are dazzled audiences      -> 79 ('O')
    # 20: Shout it!                       -> prints 79
    # 21: Rock is electric heaven         -> 86 ('V')
    # 22: Scream it!                      -> prints 86
    # 23: Tommy is jukebox god            -> 73 ('I')
    # 24: Say it!                         -> prints 73

    numbers = [66, 79, 78, 74, 79, 86, 73]
    word = "".join(chr(n) for n in numbers)
    print(f"[*] Decoded word: {word}", flush=True)
    
    flag = f"academy{{{word}}}"
    print(f"[+] Flag: {flag}", flush=True)
    
    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag)
    print(f"[+] Saved flag to {flag_path}", flush=True)
    
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{BONJOVI}
```
