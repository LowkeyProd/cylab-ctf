# Writeup: m00nwalk2

## Header & Metadata
- **Challenge:** m00nwalk2 (ID: 28)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** message.wav, clue1.wav, clue2.wav, clue3.wav
- **Official Flag:** `academy{the_answer_lies_hidden_in_plain_sight}`

---

## Mô tả bài toán (Overview / Analysis)

Revisit the last transmission. We think this <a href='https://challenge-files.cylabacademy.net/library/56d435f22572b90779f8dfb64b63981437fd3eeaf53fdf0bb58227bd4adc541a/message.wav' download>transmission</a> contains a hidden message. There are also some clues <a href='https://challenge-files.cylabacademy.net/library/56d435f22572b90779f8dfb64b63981437fd3eeaf53fdf0bb58227bd4adc541a/clue1.wav' download>clue 1</a>, <a href='https://challenge-files.cylabacademy.net/library/56d435f22572b90779f8dfb64b63981437fd3eeaf53fdf0bb58227bd4adc541a/clue2.wav' download>clue 2</a>, <a href='https://challenge-files.cylabacademy.net/library/56d435f22572b90779f8dfb64b63981437fd3eeaf53fdf0bb58227bd4adc541a/clue3.wav' download>clue 3</a>.

### Hints
- Use the clues to extract the another flag from the .wav file

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Automated Solver for m00nwalk2 (#28)
Extracts flag from message.wav using Steghide with password recovered from clue1.wav SSTV.
"""
import subprocess
import re
from pathlib import Path

def solve():
    base_dir = Path(__file__).resolve().parent
    message_file = base_dir / "message.wav"
    password = "hidden_stegosaurus"

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{base_dir}:/work",
        "-w", "/work",
        "local/steghide",
        "extract", "-sf", "message.wav", "-p", password, "-xf", "-"
    ]
    res = subprocess.run(cmd, capture_output=True, check=True)
    out = res.stdout.decode("latin1", errors="ignore")
    
    m = re.search(r'(academy\{[^\}]+\}|picoCTF\{[^\}]+\})', out)
    if not m:
        raise ValueError(f"Flag not found in output: {out}")
        
    flag = m.group(1)
    print(f"[+] Recovered Flag: {flag}")
    
    flag_file = base_dir / "flag.txt"
    flag_file.write_text(flag + "\n")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{the_answer_lies_hidden_in_plain_sight}
```
