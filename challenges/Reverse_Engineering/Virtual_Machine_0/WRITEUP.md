# Writeup: Virtual Machine 0

## Header & Metadata
- **Challenge:** Virtual Machine 0 (ID: 385)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** Virtual-Machine-0.zip, input.txt
- **Official Flag:** `academy{g34r5_0f_m0r3_d1e94fd4}`

---

## Mô tả bài toán (Overview / Analysis)
Can you crack this black box?
We grabbed this design doc from enemy servers: 
<a href='https://challenge-files.cylabacademy.net/library/0cbadfbf9547804ff96f633ed2e5b067215c9bccfa181635b1018e135cd884f3/Virtual-Machine-0.zip' download>Download</a>. We know that the rotation
of the red axle is input and the rotation of the blue axle is output. The
following input gives the flag as output: <a href='https://challenge-files.cylabacademy.net/library/0cbadfbf9547804ff96f633ed2e5b067215c9bccfa181635b1018e135cd884f3/input.txt' download>Download</a>.

### Hints
- Rotating the axle that number of times is obviously not feasible. Can you
  model the mathematical relationship between red and blue?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Virtual Machine 0 (#385)
Category: Reverse Engineering
"""
import os
import sys
from pathlib import Path

def parse_connection_cfg(cfg_path="connection.cfg"):
    config = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    config[key.strip()] = val.strip()
    return config

def solve():
    print("[*] Solving Virtual Machine 0...", flush=True)
    _cfg = parse_connection_cfg()
    
    # Read input rotation count
    input_path = Path("input.txt")
    if not input_path.exists():
        print("[-] input.txt not found!", flush=True)
        return ""
    
    with open(input_path, "r") as f:
        input_num = int(f.read().strip())
    
    print(f"[*] Input rotations: {input_num}", flush=True)
    
    # The mechanical gear train consists of:
    # - Red axle (input): 40-tooth gear (part 3649)
    # - Idler axle: 8-tooth gear (part 3647)
    # - Blue axle (output): 8-tooth gear (part 3647)
    # Gear ratio: (40 / 8) * (-8 / 8) * (-1 for idler inversion) = +5
    ratio = 5
    output_num = input_num * ratio
    
    # Convert output integer to big-endian bytes
    flag_bytes = output_num.to_bytes((output_num.bit_length() + 7) // 8, byteorder="big")
    flag = flag_bytes.decode("ascii", errors="ignore")
    
    print(f"[+] Discovered flag: {flag}", flush=True)
    
    # Save to flag.txt
    with open("flag.txt", "w") as f:
        f.write(flag)
    print("[+] Flag written to flag.txt", flush=True)
    
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{g34r5_0f_m0r3_d1e94fd4}
```
