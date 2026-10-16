# WebNet1 - CTF Writeup

## 1. Header & Metadata
- **Challenge Title:** WebNet1
- **Challenge ID:** 42
- **Event / Platform:** CyLab Academy (ported from picoCTF)
- **Category:** Forensics
- **Difficulty:** Hard
- **Provided Files:** `webnet1-capture.pcap`, `picopico.key`
- **Official Flag:** `academy{honey.roasted.peanuts}`

---

## 2. Overview / Analysis
The challenge provides a packet capture (`webnet1-capture.pcap`) and an RSA private key file (`picopico.key`). The user is tasked with recovering the flag hidden inside the captured traffic.

Inspection reveals:
- The capture contains encrypted TLS 1.2 traffic passing over port 443 between a client (`128.237.140.23`) and a web server (`172.31.22.220`).
- Because an RSA key exchange cipher suite is used, supplying the server's private key (`picopico.key`) enables passive decryption of the entire TLS session.
- An HTTP response header `Pico-Flag` contains a decoy flag: `academy{this.is.not.your.flag.anymore}`.
- Therefore, the real flag must be located inside one of the transferred HTTP resources or assets.

---

## 3. Technical Deep-Dive

### Decrypting the TLS Session
In modern Wireshark / `tshark` (version 3.0+), TLS RSA keys are loaded via the User Accessible Table (UAT) `rsa_keys` option:
```bash
tshark -r webnet1-capture.pcap -o 'uat:rsa_keys:"picopico.key",""' -Y http
```

This successfully exposes decrypted HTTP streams:
- `GET /second.html`
- `GET /starter-template.css`
- `GET /vulture.jpg`
- `GET /favicon.ico` (404 Not Found)

### Decoy Flag in Response Headers
Inspecting the HTTP headers across all responses reveals:
```http
Pico-Flag: academy{this.is.not.your.flag.anymore}
```
This is a trap/decoy, implying that the actual flag is embedded elsewhere in the payload.

### Asset Extraction & Steganographic / Metadata Analysis
Using `tshark`'s `--export-objects "http,<dest_dir>"` capability, the transmitted files were dumped into disk:
- `second.html`
- `starter-template.css`
- `vulture.jpg`

Inspecting `vulture.jpg` with `strings` or viewing its Exif metadata (specifically TIFF tag `0x013b` / Artist):
```text
00000070: 0000 0001 0000 0001 6163 6164 656d 797b  ........academy{
00000080: 686f 6e65 792e 726f 6173 7465 642e 7065  honey.roasted.pe
00000090: 616e 7574 737d 0000 ffe2 021c 4943 435f  anuts}......ICC_
```
The genuine flag is embedded directly within the Exif metadata of `vulture.jpg`:
`academy{honey.roasted.peanuts}`.

---

## 4. Solve Script (`solve.py`)
Below is the complete, self-contained Python script implementing automated TLS decryption, object export, and flag retrieval:

```python
#!/usr/bin/env python3
"""
WebNet1 Solution Script
Extracts decrypted HTTP objects using tshark and TLS private key,
then searches for the flag in exported assets (vulture.jpg Exif metadata).
"""

import os
import re
import shutil
import subprocess
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PCAP_FILE = os.path.join(BASE_DIR, "webnet1-capture.pcap")
KEY_FILE = os.path.join(BASE_DIR, "picopico.key")
OUTPUT_DIR = os.path.join(BASE_DIR, "exported_objects")
FLAG_FILE = os.path.join(BASE_DIR, "flag.txt")


def find_tshark():
    tshark = shutil.which("tshark")
    if tshark:
        return tshark
    common_paths = [
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
    ]
    for p in common_paths:
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    raise RuntimeError("tshark binary not found on the system.")


def solve():
    tshark = find_tshark()

    if os.path.exists(OUTPUT_DIR):
        shutil.rmtree(OUTPUT_DIR)
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Export HTTP objects using tshark and RSA private key
    # Option: uat:rsa_keys:"\"<keyfile>\",\"<password>\""
    cmd = [
        tshark,
        "-r",
        PCAP_FILE,
        "-o",
        f'uat:rsa_keys:"{KEY_FILE}",""',
        "--export-objects",
        f"http,{OUTPUT_DIR}",
    ]

    subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )

    pattern = re.compile(rb"(academy\{[^}]+\}|picoCTF\{[^}]+\})")
    fake_flag = b"academy{this.is.not.your.flag.anymore}"
    flag = None

    for root, _, files in os.walk(OUTPUT_DIR):
        for fname in sorted(files):
            fpath = os.path.join(root, fname)
            with open(fpath, "rb") as f:
                content = f.read()
                matches = pattern.findall(content)
                for match in matches:
                    if match != fake_flag:
                        flag = match.decode("utf-8")
                        break
            if flag:
                break

    if not flag:
        raise ValueError("Flag not found in exported objects.")

    with open(FLAG_FILE, "w") as f:
        f.write(flag + "\n")

    print(f"Flag found: {flag}")
    return flag


if __name__ == "__main__":
    solve()
```

---

## 5. Output & Verification
Executing `solve.py`:
```text
$ python3 solve.py
Flag found: academy{honey.roasted.peanuts}
```

Contents of `flag.txt`:
```text
$ cat flag.txt
academy{honey.roasted.peanuts}
```
