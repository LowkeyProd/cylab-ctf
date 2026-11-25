# Writeup: WhitePages

## Header & Metadata
- **Challenge:** WhitePages (ID: 51)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** whitepages.txt
- **Official Flag:** `academy{not_all_spaces_are_created_equal_19fc1787ee14ef2c56ee0cddc142a0d9}`

---

## Mô tả bài toán (Overview / Analysis)

I stopped using YellowPages and moved onto WhitePages... but <a href='https://challenge-files.cylabacademy.net/library/53f38374e47a48424dc7e9100aba4e4b42a590f3921cfc31188171ae7d6d61e3/whitepages.txt' download>the page they gave me</a> is all blank!

### Hints
- There is data encoded somewhere... there might be an online decoder.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for WhitePages (Forensics)
Extracts hidden binary data encoded with Unicode EM Space (U+2003) and ASCII Space (U+0020).
"""
import os
import re
import sys

def solve():
    file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "whitepages.txt")
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found!", file=sys.stderr)
        sys.exit(1)

    with open(file_path, "rb") as f:
        data = f.read()

    # EM SPACE (U+2003) in UTF-8 is \xe2\x80\x83 -> '0'
    # ASCII SPACE (U+0020) is \x20 -> '1'
    bit_data = data.replace(b"\xe2\x80\x83", b"0").replace(b" ", b"1")
    bits = [chr(c) for c in bit_data if c in (ord('0'), ord('1'))]
    bitstring = "".join(bits)

    decoded_bytes = bytearray()
    for i in range(0, len(bitstring), 8):
        byte_chunk = bitstring[i:i+8]
        if len(byte_chunk) == 8:
            decoded_bytes.append(int(byte_chunk, 2))

    decoded_text = decoded_bytes.decode("utf-8", errors="ignore")
    
    match = re.search(r"(?:academy|picoCTF)\{[^}]+\}", decoded_text)
    if not match:
        print("[-] Flag not found in decoded text!", file=sys.stderr)
        sys.exit(1)

    flag = match.group(0)
    print(f"[+] Flag found: {flag}")

    flag_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flag.txt")
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag + "\n")

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{not_all_spaces_are_created_equal_19fc1787ee14ef2c56ee0cddc142a0d9}
```
