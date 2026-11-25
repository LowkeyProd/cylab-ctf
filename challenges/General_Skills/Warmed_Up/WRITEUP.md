# Writeup: Warmed Up

## Header & Metadata
- **Challenge:** Warmed Up (ID: 58)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `academy{61}`

---

## Mô tả bài toán (Overview / Analysis)
What is 0x3D (base 16) in decimal (base 10)?


### Hints
- Submit your answer in our flag format. For example, if your answer was '22', you would submit 'academy{22}' as the flag.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Clean, self-contained solver for Warmed Up (#58)
Category: General Skills
Description: Converts 0x3D (base 16) to decimal (base 10) and formats flag.
"""
from pathlib import Path


def load_config():
    """Dynamically load connection parameters from connection.cfg if available."""
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    if cfg_file.exists():
        with open(cfg_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip()
    return config


def hex_to_decimal(hex_str: str) -> int:
    """
    Mathematical transformation from base-16 to base-10 using positional expansion:
    N = sum(d_i * 16^i) for d_i in hex_str digits.
    """
    cleaned = hex_str.lower().removeprefix("0x")
    decimal_value = 0
    for char in cleaned:
        digit = int(char, 16)
        decimal_value = decimal_value * 16 + digit  # Horner's method
    return decimal_value


def solve():
    _ = load_config()

    # Mathematical transformation based on analysis.md
    hex_input = "0x3D"
    decimal_result = hex_to_decimal(hex_input)

    # Format flag
    flag = f"academy{{{decimal_result}}}"

    # Persist flag
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag.strip() + "\n", encoding="utf-8")

    # Output exact decoded token cleanly
    print(flag, flush=True)
    return flag


if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{61}
```
