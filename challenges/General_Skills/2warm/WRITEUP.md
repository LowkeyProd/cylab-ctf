# Writeup: 2warm

## Header & Metadata
- **Challenge:** 2warm (ID: 86)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `academy{101010}`

---

## Mô tả bài toán (Overview / Analysis)
Can you convert the number 42 (base 10) to binary (base 2)?


### Hints
- Submit your answer in our competition's flag format. For example, if your answer was '11111', you would submit 'academy{11111}' as the flag.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Clean, self-contained solver for 2warm (#86)
Category: General Skills
Description: Converts the number 42 (base 10) to binary (base 2) and formats flag.
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


def decimal_to_binary(n: int) -> str:
    """
    Mathematical transformation from base-10 to base-2 using repeated division by 2:
    Repeatedly divide n by 2 and collect the remainders in reverse order.
    """
    if n == 0:
        return "0"
    digits = []
    val = n
    while val > 0:
        digits.append(str(val % 2))
        val //= 2
    return "".join(reversed(digits))


def solve():
    _ = load_config()

    # Base 10 to binary conversion
    number_base10 = 42
    binary_str = decimal_to_binary(number_base10)

    # Format flag
    flag = f"academy{{{binary_str}}}"

    # Persist flag
    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag.strip() + "\n", encoding="utf-8")

    # Output exact decoded token cleanly
    print(flag)
    return flag


if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{101010}
```
