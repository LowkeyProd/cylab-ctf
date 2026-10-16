# Writeup: Wave a flag

## Header & Metadata
- **Challenge:** Wave a flag (ID: 170)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `https://challenge-files.cylabacademy.net/library/7370c7c01b6da3581f45bd49c1e76752891ec49a2da06ba55ae6db18e5d036a4/warm`
- **Attached Files:** warm
- **Official Flag:** `academy{b1scu1ts_4nd_gr4vy_57d8c79}`

---

## Mô tả bài toán (Overview / Analysis)
Can you invoke help flags for a tool or binary? This program has extraordinarily helpful information...
<a href='https://challenge-files.cylabacademy.net/library/7370c7c01b6da3581f45bd49c1e76752891ec49a2da06ba55ae6db18e5d036a4/warm' download>warm</a>

### Hints
- This program will only work in the webshell or another Linux computer.
- To get the file accessible in your shell, enter the following in the Terminal prompt: `$ wget <URL here>`, where the url can be found in the details section.
- Run this program by entering the following in the Terminal prompt: `$ ./warm`, but you'll first have to make it executable with `$ chmod +x warm`
- -h and --help are the most common arguments to give to programs to get more information from them!
- Not every program implements help features like -h and --help.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Wave a flag (#170)
Category: General Skills
"""
import requests
import re
from pathlib import Path

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/7370c7c01b6da3581f45bd49c1e76752891ec49a2da06ba55ae6db18e5d036a4/warm"

def solve():
    url = get_target_url().rstrip('/')
    print(f"[*] Target URL: {url}")
    try:
        r = requests.get(url, timeout=10)
        flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
        m = flag_pattern.findall(r.text)
        if m:
            flag = m[0]
            print(f"[+] Flag found: {flag}")
            (Path(__file__).resolve().parent / "flag.txt").write_text(flag + "\n")
            return flag
    except Exception as e:
        print(f"[-] Request error: {e}")
    return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{b1scu1ts_4nd_gr4vy_57d8c79}
```
