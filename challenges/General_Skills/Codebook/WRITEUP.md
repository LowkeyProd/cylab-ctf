# Writeup: Codebook

## Header & Metadata
- **Challenge:** Codebook (ID: 238)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** code.py, codebook.txt
- **Official Flag:** `academy{c0d3b00k_455157_3bd506e1}`

---

## Mô tả bài toán (Overview / Analysis)
Run the Python script `code.py` in the same directory as `codebook.txt`.
- <a href='https://challenge-files.cylabacademy.net/library/8734bd5ef924fd625fb3885845b5ad980f92f7afc51f1ec53a7c69d7b31f615c/code.py' download>Download code.py</a>
- <a href='https://challenge-files.cylabacademy.net/library/8734bd5ef924fd625fb3885845b5ad980f92f7afc51f1ec53a7c69d7b31f615c/codebook.txt' download>Download codebook.txt</a>

### Hints
- On the webshell, use `ls` to see if both files are in the directory you are
  in
- The `str_xor` function does not need to be reverse engineered for this
  challenge.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity following writeup instructions.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Codebook (#238)
Category: General Skills
"""
from pathlib import Path
import code as challenge_code

def solve():
    print("[*] Solving Codebook...", flush=True)
    codebook_path = Path(__file__).parent / "codebook.txt"
    codebook = codebook_path.read_text(encoding="utf-8")
    
    password = (
        codebook[4] + codebook[14] + codebook[13] + codebook[14] +
        codebook[23] + codebook[25] + codebook[16] + codebook[0] +
        codebook[25]
    )
    flag = challenge_code.str_xor(challenge_code.flag_enc, password)
    print(f"[*] Recovered flag: {flag}", flush=True)

    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag.strip(), encoding="utf-8")
    print(f"[*] Flag written to {flag_path}", flush=True)
    return flag.strip()

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{c0d3b00k_455157_3bd506e1}
```
