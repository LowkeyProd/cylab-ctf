# Writeup: MultiCode

## Header & Metadata
- **Challenge:** MultiCode (ID: 710)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** message.txt
- **Official Flag:** `academy{nested_enc0ding_beda96b2}`

---

## Mô tả bài toán (Overview / Analysis)
We intercepted a suspiciously encoded message, but it’s clearly hiding a flag. No encryption, just multiple layers of obfuscation. Can you peel back the layers and reveal the truth?
Download the <a href='https://challenge-files.cylabacademy.net/library/86cd4681b2ee6156ddeabab2fd8e3158faad82aa82f5a0d6f8916696466dc75e/message.txt' download>message</a>.

### Hints
- The flag has been wrapped in several layers of common encodings such as ROT13, URL encoding, Hex, and Base64. Can you figure out the order to peel them back?
- A tool like CyberChef can be interesting.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for MultiCode (#710)
Category: General Skills
"""
import base64
import codecs
import re
import urllib.parse
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("URL=") and len(line.split("=", 1)) > 1:
                val = line.split("=", 1)[1].strip()
                if val:
                    return val
    return None

def decode_layers(raw_text):
    text = raw_text.strip()
    print(f"[*] Raw text: {text}", flush=True)

    # Layer 1: Base64 decode
    try:
        b64_decoded = base64.b64decode(text).decode('utf-8')
        print(f"[*] Layer 1 (Base64 decoded): {b64_decoded}", flush=True)
    except Exception as e:
        print(f"[-] Base64 decode failed: {e}", flush=True)
        b64_decoded = text

    # Layer 2: Hex decode
    try:
        hex_decoded = bytes.fromhex(b64_decoded).decode('utf-8')
        print(f"[*] Layer 2 (Hex decoded): {hex_decoded}", flush=True)
    except Exception as e:
        print(f"[-] Hex decode failed: {e}", flush=True)
        hex_decoded = b64_decoded

    # Layer 3: URL decode
    try:
        url_decoded = urllib.parse.unquote(hex_decoded)
        print(f"[*] Layer 3 (URL decoded): {url_decoded}", flush=True)
    except Exception as e:
        print(f"[-] URL decode failed: {e}", flush=True)
        url_decoded = hex_decoded

    # Layer 4: ROT13 decode
    try:
        rot13_decoded = codecs.decode(url_decoded, 'rot_13')
        print(f"[*] Layer 4 (ROT13 decoded): {rot13_decoded}", flush=True)
    except Exception as e:
        print(f"[-] ROT13 decode failed: {e}", flush=True)
        rot13_decoded = url_decoded

    return rot13_decoded

def solve():
    target_url = get_target_url()
    raw_content = None

    if target_url:
        print(f"[*] Fetching encoded message from target URL: {target_url}", flush=True)
        try:
            r = requests.get(target_url, timeout=10)
            if r.status_code == 200 and r.text.strip():
                raw_content = r.text.strip()
                print("[+] Successfully downloaded message from remote URL.", flush=True)
        except Exception as e:
            print(f"[-] Failed to fetch from URL: {e}", flush=True)

    if not raw_content:
        msg_file = Path(__file__).resolve().parent / "message.txt"
        if msg_file.exists():
            print("[*] Reading local message.txt", flush=True)
            raw_content = msg_file.read_text().strip()

    if not raw_content:
        print("[-] Error: No message content available.", flush=True)
        return None

    decoded = decode_layers(raw_content)

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    matches = flag_pattern.findall(decoded)

    valid_flags = [f for f in matches if not any(d in f.lower() for d in ['decoy', 'fake', 'honeypot', 'dummy'])]

    if valid_flags:
        flag = valid_flags[0]
        print(f"[+] Flag found: {flag}", flush=True)
        out_file = Path(__file__).resolve().parent / "flag.txt"
        out_file.write_text(flag + "\n")
        return flag
    else:
        print("[-] Flag not found in decoded output.", flush=True)
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{nested_enc0ding_beda96b2}
```
