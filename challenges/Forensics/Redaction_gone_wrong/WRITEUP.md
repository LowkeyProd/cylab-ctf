# Writeup: Redaction gone wrong

## Header & Metadata
- **Challenge:** Redaction gone wrong (ID: 290)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** Financial_Report_for_ABC_Labs.pdf
- **Official Flag:** `academy{C4n_Y0u_S33_m3_fully}`

---

## Mô tả bài toán (Overview / Analysis)
Now you DON’T see me.
This <a href='https://challenge-files.cylabacademy.net/library/455e6e9581a9272cf0cd6a8f2da0a7cdcfefdb52dc7a7f9c09a27705e2c94103/Financial_Report_for_ABC_Labs.pdf' download>report</a> has some
critical data in it, some of which have been redacted correctly, while some
were not. Can you find an important key that was not redacted properly?

### Hints
- How can you be sure of the redaction?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity analyzing & repairing solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
import re
import zlib
import base64
from pathlib import Path

def solve():
    pdf_path = Path("Financial_Report_for_ABC_Labs.pdf")
    content = pdf_path.read_bytes()
    
    start_idx = content.find(b"stream")
    flag = ""
    if start_idx != -1:
        start_idx += len("stream")
        while content[start_idx:start_idx+1] in (b'\r', b'\n'):
            start_idx += 1
        end_idx = content.find(b"endstream", start_idx)
        stream_data = content[start_idx:end_idx].strip()
        
        if not stream_data.startswith(b'<~'):
            stream_data = b'<~' + stream_data
        if not stream_data.endswith(b'~>'):
            stream_data = stream_data + b'~>'
            
        decoded = base64.a85decode(stream_data, adobe=True)
        decompressed = zlib.decompress(decoded).decode('latin-1', errors='replace')
        
        match = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', decompressed)
        if match:
            flag = match.group(1)

    print(f"[*] Found flag: {flag}")
    if flag:
        Path("flag.txt").write_text(flag, encoding="utf-8")
        print("[+] Wrote flag to flag.txt")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{C4n_Y0u_S33_m3_fully}
```
