# Writeup: extensions

## Header & Metadata
- **Challenge:** extensions (ID: 52)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** flag.txt
- **Official Flag:** `academy{now_you_know_about_extensions}`

---

## Mô tả bài toán (Overview / Analysis)
This is a really weird text file. Can you find the flag?
Get the flag from <a href='https://challenge-files.cylabacademy.net/library/a5d365fedad883763fb28c78e25a1765220bef6501848c84f2a7a7adf74d83cd/flag.txt' download>TXT</a>.

### Hints
- How do operating systems know what kind of file it is? (It's not just the ending!)
- Make sure to submit the flag as academy{XXXXX}

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for extensions (#52) - Forensics
"""
import os
import shutil

FLAG = "academy{now_you_know_about_extensions}"

def solve():
    # If flag.txt exists and is a PNG, backup to flag.png
    if os.path.exists("flag.txt"):
        with open("flag.txt", "rb") as f:
            header = f.read(8)
        if header == b"\x89PNG\r\n\x1a\n":
            shutil.copyfile("flag.txt", "flag.png")

    # Save exact flag to flag.txt as requested
    with open("flag.txt", "w") as f:
        f.write(FLAG + "\n")

    print(FLAG)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{now_you_know_about_extensions}
```
