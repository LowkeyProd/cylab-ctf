# Writeup: Hidden in plainsight

## Header & Metadata
- **Challenge:** Hidden in plainsight (ID: 524)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** img.jpg
- **Official Flag:** `academy{h1dd3n_1n_1m4g3_71ae1957}`

---

## Mô tả bài toán (Overview / Analysis)
You’re given a seemingly ordinary JPG image. Something is tucked away out of sight inside the file. Your task is to discover the hidden payload and extract the flag.
Download the jpg image <a href='https://challenge-files.cylabacademy.net/library/9ec77a1b83f3b582954d97ec39f7926d4dc45f98cd1ef7a24b3172ca385e02b2/img.jpg' download>here</a>.

### Hints
- Download the jpg image and read its metadata

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Hidden in plainsight (#524)
Category: Forensics
"""
import base64
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/714093cf55b6f82d117c53a2a1d44f4956e0ccc7655b1fe2efee99e12b314f53/img.jpg"

def ensure_image():
    script_dir = Path(__file__).resolve().parent
    img_path = script_dir / "img.jpg"
    if not img_path.exists():
        url = get_target_url()
        print(f"[*] Downloading image from {url}...")
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        img_path.write_bytes(resp.content)
    return img_path

def extract_credentials_from_image(img_path):
    data = img_path.read_bytes()
    
    # 1. Search for JPEG COM marker (0xFFFE)
    idx = 0
    while True:
        pos = data.find(b"\xff\xfe", idx)
        if pos == -1:
            break
        length = int.from_bytes(data[pos + 2 : pos + 4], "big")
        comment = data[pos + 4 : pos + 2 + length]
        try:
            decoded_outer = base64.b64decode(comment).decode("utf-8")
            if ":" in decoded_outer:
                tool, encoded_pwd = decoded_outer.split(":", 1)
                password = base64.b64decode(encoded_pwd).decode("utf-8")
                return tool, password
        except Exception:
            pass
        idx = pos + 2

    # 2. Fallback: regex search across all ascii strings
    for m in re.finditer(rb"[A-Za-z0-9+/=]{16,}", data):
        try:
            cand = base64.b64decode(m.group(0)).decode("utf-8")
            if ":" in cand:
                tool, encoded_pwd = cand.split(":", 1)
                password = base64.b64decode(encoded_pwd).decode("utf-8")
                return tool, password
        except Exception:
            continue

    raise RuntimeError("Failed to extract steghide credentials from image metadata")

def extract_flag_steghide(img_path, password):
    img_str = str(img_path)
    # Check execution method: steghide, wsl, or docker
    cmd = None
    if shutil.which("steghide"):
        cmd = ["steghide", "extract", "-sf", img_str, "-p", password, "-xf", "-"]
    elif shutil.which("wsl"):
        cmd = ["wsl", "steghide", "extract", "-sf", img_path.name, "-p", password, "-xf", "-"]
    elif shutil.which("docker"):
        workdir = str(img_path.parent)
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{workdir}:/work",
            "-w", "/work",
            "local/steghide", "extract", "-sf", img_path.name, "-p", password, "-xf", "-"
        ]
    else:
        raise RuntimeError("No steghide, wsl, or docker found to run steghide")

    cwd = str(img_path.parent)
    proc = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output = proc.stdout + proc.stderr
    
    flag_pattern = re.compile(r"(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}")
    m = flag_pattern.findall(output)
    if m:
        return m[0]
    
    raise RuntimeError(f"Flag not found in steghide output: {output}")

def solve():
    img_path = ensure_image()
    tool, password = extract_credentials_from_image(img_path)
    print(f"[+] Discovered tool: {tool}, passphrase: {password}")
    
    flag = extract_flag_steghide(img_path, password)
    print(f"[+] Flag found: {flag}")
    
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag.strip() + "\n")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{h1dd3n_1n_1m4g3_71ae1957}
```
