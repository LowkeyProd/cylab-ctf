# Writeup: Surfing the Waves

## Header & Metadata
- **Challenge:** Surfing the Waves (ID: 117)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** main.wav
- **Official Flag:** `academy{mU21C_1s_1337_63f2299a}`

---

## Mô tả bài toán (Overview / Analysis)
While you're going through the FBI's servers, you stumble across their incredible taste in music. One you found is particularly interesting, see if you can find the flag!
<a href='https://challenge-files.cylabacademy.net/library/499b4db147ad23851284018b3968d51770e0ae878d2adfd527be0c6aedc6d248/main.wav' download>main.wav</a>

### Hints
- Music is cool, but what other kinds of waves are there?
- Look deep below the surface

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Surfing the Waves (#117)
Category: Forensics
"""
import wave
import struct
import string
import re
from pathlib import Path

def solve():
    print("[*] Solving Surfing the Waves...", flush=True)
    wav_path = Path(__file__).parent / "main.wav"
    
    with wave.open(str(wav_path), 'rb') as w:
        nframes = w.getnframes()
        frames = w.readframes(nframes)
        samples = struct.unpack(f"<{nframes}h", frames)
    
    # Each sample was encoded as: 1000 + int(hex_digit) * 500 + noise
    # Reverse mapping:
    # hex_digit = (sample - 1000) // 500 = sample // 500 - 2
    hex_str = ''.join(string.hexdigits[s // 500 - 2] for s in samples)
    decoded_text = bytes.fromhex(hex_str).decode('utf-8')
    
    match = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', decoded_text)
    if not match:
        raise ValueError("Flag pattern not found in decoded payload!")
    
    flag = match.group(1)
    print(f"[+] Flag found: {flag}", flush=True)
    
    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{mU21C_1s_1337_63f2299a}
```
