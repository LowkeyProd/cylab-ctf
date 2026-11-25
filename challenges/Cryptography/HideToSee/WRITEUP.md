# Writeup: HideToSee

## Header & Metadata
- **Challenge:** HideToSee (ID: 351)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** atbash.jpg
- **Official Flag:** `academy{atbash_crack_02f11bb3}`

---

## Mô tả bài toán (Overview / Analysis)
How about some hide and seek heh?
Look at this image <a href='https://challenge-files.cylabacademy.net/library/d1a6b6365f32679d90a52e42234c7bad12bdfb9ac5e87598af9f1202ee047227/atbash.jpg' download>here</a>.

### Hints
- Download the image  and try to extract it.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for HideToSee (#351)
Category: Cryptography
"""
import shutil
import subprocess
from pathlib import Path

def atbash_cipher(text: str) -> str:
    result = []
    for c in text:
        if 'a' <= c <= 'z':
            result.append(chr(ord('z') - (ord(c) - ord('a'))))
        elif 'A' <= c <= 'Z':
            result.append(chr(ord('Z') - (ord(c) - ord('A'))))
        else:
            result.append(c)
    return ''.join(result)

def solve():
    print("[*] Solving HideToSee...")
    script_dir = Path(__file__).resolve().parent
    image_file = script_dir / "atbash.jpg"
    extracted_file = script_dir / "encrypted.txt"

    if not extracted_file.exists():
        # Try running steghide directly or via wsl
        steghide_cmd = None
        if shutil.which("steghide"):
            steghide_cmd = ["steghide", "extract", "-sf", str(image_file), "-p", "", "-f"]
        elif shutil.which("wsl"):
            wsl_img = str(image_file).replace("\\", "/")
            if ":" in wsl_img:
                drive, rest = wsl_img.split(":", 1)
                wsl_img = f"/mnt/{drive.lower()}{rest}"
            steghide_cmd = ["wsl", "steghide", "extract", "-sf", wsl_img, "-p", "", "-f"]

        if steghide_cmd:
            subprocess.run(steghide_cmd, cwd=str(script_dir), check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if not extracted_file.exists():
        raise FileNotFoundError(f"Could not extract or locate {extracted_file}")

    ciphertext = extracted_file.read_text().strip()
    flag = atbash_cipher(ciphertext)
    print(f"[+] Flag found: {flag}")

    flag_file = script_dir / "flag.txt"
    flag_file.write_text(flag)
    print(f"[+] Saved flag to {flag_file}")

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{atbash_crack_02f11bb3}
```
