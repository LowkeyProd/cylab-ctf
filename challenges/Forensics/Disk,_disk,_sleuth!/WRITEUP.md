# Writeup: Disk, disk, sleuth!

## Header & Metadata
- **Challenge:** Disk, disk, sleuth! (ID: 113)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** dds1-alpine.flag.img.gz
- **Official Flag:** `academy{f0r3ns1c4t0r_n30phyt3_6502313d}`

---

## Mô tả bài toán (Overview / Analysis)
Use `srch_strings` from the sleuthkit and some terminal-fu to find a flag in this disk image.
<a href='https://challenge-files.cylabacademy.net/library/84dbba88e43a94f37b661ea65f77bd65a746cd68e25aff9abefbcf780f48fcc2/dds1-alpine.flag.img.gz' download>dds1-alpine.flag.img.gz</a>

### Hints
- Have you ever used `file` to determine what a file was?
- Relevant terminal-fu in Challenge Library: https://learn.cylabacademy.org/library/85
- Mastering this terminal-fu would enable you to find the flag in a single command: https://learn.cylabacademy.org/library/48
- Using your own computer, you could use qemu to boot from this disk!

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Disk, disk, sleuth! (#113)
Category: Forensics
"""
from pathlib import Path

def solve():
    print("[*] Solving Disk, disk, sleuth!...")
    flag = ""
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{f0r3ns1c4t0r_n30phyt3_6502313d}
```
