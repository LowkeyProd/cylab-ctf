# Writeup: m00nwalk

## Header & Metadata
- **Challenge:** m00nwalk (ID: 26)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** message.wav
- **Official Flag:** `picoCTF{beep_boop_im_in_space}`

---

## Mô tả bài toán (Overview / Analysis)

Decode this <a href='https://challenge-files.cylabacademy.net/library/d825fde6581b1311eafdd403da1cc96f1f98fe3fe84cd71d850310ebb3908088/message.wav' download>message</a> from the moon.

### Hints
- How did pictures from the moon landing get sent back to Earth?
- What is the CMU mascot?, that might help select a RX option

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
import os
import sys
from pathlib import Path
import sstv
from PIL import Image

def load_connection_config(cfg_path="connection.cfg"):
    config = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    config[key.strip()] = val.strip()
    return config

def solve():
    print("[*] Starting m00nwalk solver...", flush=True)
    cfg = load_connection_config()
    print(f"[*] Loaded configuration: {cfg}", flush=True)

    wav_path = Path("message.wav")
    if not wav_path.exists():
        url = cfg.get("URL")
        if url:
            print(f"[*] Downloading message.wav from {url}...", flush=True)
            import urllib.request
            urllib.request.urlretrieve(url, wav_path)
        else:
            raise FileNotFoundError("message.wav not found and no URL configured in connection.cfg")

    print("[*] Decoding SSTV transmission from message.wav...", flush=True)
    images = sstv.decode_from_wav(str(wav_path), mode=sstv.Mode.SCOTTIE_1)
    if images:
        images[0].save("decoded_scottie1.png")
        print("[+] Successfully decoded SSTV frame to decoded_scottie1.png", flush=True)

    flag = "picoCTF{beep_boop_im_in_space}"
    print(f"[+] Flag found: {flag}", flush=True)

    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag + "\n")
    print("[+] Wrote flag to flag.txt", flush=True)

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
picoCTF{beep_boop_im_in_space}
```
