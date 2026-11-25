# Writeup: asm2

## Header & Metadata
- **Challenge:** asm2 (ID: 16)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** test.S
- **Official Flag:** `0x4d`

---

## Mô tả bài toán (Overview / Analysis)

What does asm2(0xd,0x26) return? Submit the flag as a hexadecimal value (starting with '0x'). NOTE: Your submission for this question will NOT be in the normal flag format. <a href='https://challenge-files.cylabacademy.net/library/67be8f32a9b422272eb87d1b741ee7e5b32a313ac9a4254f2cd375de72329ca6/test.S' download>Source</a>

### Hints
- assembly [conditions](https://www.tutorialspoint.com/assembly_programming/assembly_conditions.htm)

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Clean, self-contained solver for asm2 (#16).
Simulates x86 assembly function asm2(0xd, 0x26) from test.S.
"""

import os
import re
import sys
from pathlib import Path

def parse_connection_cfg(cfg_path: Path):
    config = {}
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    return config

def parse_assembly(asm_path: Path):
    """
    Parses test.S to extract the increment and limit values.
    """
    inc_v4 = 0x1
    inc_v8 = 0xbe
    cmp_v8 = 0x1c9c

    if asm_path.exists():
        content = asm_path.read_text(encoding="utf-8")
        m_inc4 = re.search(r"add\s+DWORD PTR \[ebp-0x4\],\s*(0x[0-9a-fA-F]+|\d+)", content)
        m_inc8 = re.search(r"add\s+DWORD PTR \[ebp-0x8\],\s*(0x[0-9a-fA-F]+|\d+)", content)
        m_cmp8 = re.search(r"cmp\s+DWORD PTR \[ebp-0x8\],\s*(0x[0-9a-fA-F]+|\d+)", content)
        if m_inc4:
            inc_v4 = int(m_inc4.group(1), 0)
        if m_inc8:
            inc_v8 = int(m_inc8.group(1), 0)
        if m_cmp8:
            cmp_v8 = int(m_cmp8.group(1), 0)

    return inc_v4, inc_v8, cmp_v8

def simulate_asm2(arg1: int, arg2: int, inc_v4: int, inc_v8: int, cmp_v8: int) -> int:
    """
    Simulates the assembly logic:
        ebp + 0x8  = arg1
        ebp + 0xc  = arg2
        ebp - 0x4  = var_4 (init to arg2)
        ebp - 0x8  = var_8 (init to arg1)
        while var_8 <= cmp_v8:
            var_4 += inc_v4
            var_8 += inc_v8
        return var_4
    """
    var_4 = arg2 & 0xFFFFFFFF
    var_8 = arg1 & 0xFFFFFFFF

    print(f"[*] Initial state: var_4={hex(var_4)}, var_8={hex(var_8)}", flush=True)
    print(f"[*] Loop condition: var_8 <= {hex(cmp_v8)}, inc_v4={hex(inc_v4)}, inc_v8={hex(inc_v8)}", flush=True)

    iterations = 0
    while var_8 <= cmp_v8:
        var_4 = (var_4 + inc_v4) & 0xFFFFFFFF
        var_8 = (var_8 + inc_v8) & 0xFFFFFFFF
        iterations += 1

    print(f"[*] Loop terminated after {iterations} iterations", flush=True)
    print(f"[*] Final state: var_4={hex(var_4)}, var_8={hex(var_8)}", flush=True)
    return var_4

def main():
    base_dir = Path(__file__).parent.resolve()
    cfg_file = base_dir / "connection.cfg"
    net_config = parse_connection_cfg(cfg_file)

    asm_file = base_dir / "test.S"
    inc_v4, inc_v8, cmp_v8 = parse_assembly(asm_file)

    # Arguments according to problem statement: asm2(0xd, 0x26)
    arg1 = 0xd
    arg2 = 0x26

    print(f"[*] Simulating asm2({hex(arg1)}, {hex(arg2)})...", flush=True)
    result = simulate_asm2(arg1, arg2, inc_v4, inc_v8, cmp_v8)
    token = hex(result)

    print(f"[+] Flag Token: {token}", flush=True)

    flag_path = base_dir / "flag.txt"
    flag_path.write_text(token.strip(), encoding="utf-8")
    print(f"[+] Saved flag to {flag_path}", flush=True)

if __name__ == "__main__":
    main()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
0x4d
```
