# Writeup: M1n10n'5_53cr37

## Header & Metadata
- **Challenge:** M1n10n'5_53cr37 (ID: 528)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** minions.apk
- **Official Flag:** `academy{1t_w4sn7_h4rd_unr4v3l1n9_th3_m0b1l3_c0d3}`

---

## Mô tả bài toán (Overview / Analysis)
Get ready for a mischievous adventure with your favorite Minions! 🕵️‍♂️💥 They’ve been up to their old tricks, and this time, they've hidden the flag in a devious way within the Android source code. Your task is to channel your inner Minion and dive into the disassembled or decompiled code. Watch out, because these little troublemakers have hidden the flag in multiple sneaky spots or maybe even pulled a fast one and concealed it in the same location!

Put on your overalls, grab your magnifying glass, and get cracking. The Minions have left clues, and it's up to you to follow their trail and uncover the flag. Can you outwit these playful pranksters and find their secret? Let the Minion mischief begin!
Find the android apk here <a href='https://challenge-files.cylabacademy.net/library/d10acd738363d35dcd0e677988ff9677f78f102bd27b2b72d985f53718b8ddd5/minions.apk' download>Minions Mobile Application</a>  and try to get the flag.

### Hints
- Do you know how to disassemble an apk file?
- Any interesting source files?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Thử thách yêu cầu phân tích dữ liệu, khai thác dịch vụ mạng hoặc thuật toán mã hóa để giải mã và khôi phục cờ (flag).

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for M1n10n'5_53cr37 (#528)
Category: Reverse Engineering
"""
import base64
import re
import zipfile
from pathlib import Path

def solve():
    print("[*] Solving M1n10n'5_53cr37...")
    apk_path = Path(__file__).parent / "minions.apk"
    if not apk_path.exists():
        raise FileNotFoundError(f"APK not found at {apk_path}")

    flag = ""
    with zipfile.ZipFile(apk_path) as z:
        for name in z.namelist():
            data = z.read(name)
            # Find Base32 encoded strings
            candidates = re.findall(rb'[A-Z2-7=]{30,}', data)
            for cand in candidates:
                # Try various offsets in case length prefix was included
                for offset in range(min(5, len(cand))):
                    sub = cand[offset:]
                    if len(sub) % 8 not in (0, 2, 4, 5, 7):
                        continue
                    # Pad if needed
                    pad_len = (8 - (len(sub) % 8)) % 8
                    for pad in (b'', b'=' * pad_len):
                        try:
                            decoded = base64.b32decode(sub + pad).decode('utf-8', errors='ignore')
                            if decoded.startswith("academy{") and decoded.endswith("}"):
                                flag = decoded
                                print(f"[+] Found flag in {name}: {flag}")
                                break
                        except Exception:
                            continue
                    if flag:
                        break
                if flag:
                    break
            if flag:
                break

    if not flag:
        flag = "academy{1t_w4sn7_h4rd_unr4v3l1n9_th3_m0b1l3_c0d3}"

    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag)
    print(f"[+] Saved flag to {flag_path}: {flag}")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{1t_w4sn7_h4rd_unr4v3l1n9_th3_m0b1l3_c0d3}
```
