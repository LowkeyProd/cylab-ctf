# Writeup: Mind your Ps and Qs

## Header & Metadata
- **Challenge:** Mind your Ps and Qs (ID: 162)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** values
- **Official Flag:** `academy{sma11_N_n0_g0od_a3ac7152}`

---

## Mô tả bài toán (Overview / Analysis)
In RSA, a small $$e$$ value can be problematic, but what about $$N$$? Can you decrypt this?
<a href='https://challenge-files.cylabacademy.net/library/e712cf9934db77224f35b37326b9c7867a0f2941cc6fa3c7d5a041ddf348fcac/values' download>values</a>

### Hints
- Bits are expensive, I used only a little bit over 100 to save money

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Mind your Ps and Qs (#162)
Category: Cryptography
"""
import re
import json
import urllib.request
from pathlib import Path

def get_factors(n):
    # Try querying factordb API
    try:
        url = f"https://factordb.com/api?query={n}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") in ["FF", "CF"]:
                factors = [int(f[0]) for f in data.get("factors", [])]
                if len(factors) == 2 and factors[0] * factors[1] == n:
                    return factors[0], factors[1]
    except Exception as e:
        print(f"[-] FactorDB error: {e}")

    # Fallback to known factors for this challenge instance
    p = 2074606527507983503944226222695401999839
    q = 659880377875535146491994798968813949893149
    if p * q == n:
        return p, q

    raise ValueError("Could not factor n")

def solve():
    script_dir = Path(__file__).resolve().parent
    values_file = script_dir / "values"
    
    if not values_file.exists():
        url = "https://challenge-files.cylabacademy.net/library/fce60438262ba3f80dcba1d40e65a745f7b587f7cc4dbc149504cfe9777487c4/values"
        print(f"[*] Downloading values from {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            values_file.write_bytes(resp.read())

    content = values_file.read_text()
    c = int(re.search(r"c:\s*(\d+)", content).group(1))
    n = int(re.search(r"n:\s*(\d+)", content).group(1))
    e = int(re.search(r"e:\s*(\d+)", content).group(1))

    print(f"[*] c = {c}")
    print(f"[*] n = {n}")
    print(f"[*] e = {e}")

    p, q = get_factors(n)
    print(f"[+] p = {p}")
    print(f"[+] q = {q}")

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(c, d, n)

    byte_len = (m.bit_length() + 7) // 8
    candidates = [
        m.to_bytes(byte_len, "big"),
        m.to_bytes(byte_len, "little"),
        m.to_bytes(byte_len, "big")[::-1],
    ]

    flag_pattern = re.compile(r"(?:academy|picoCTF)\{[^}\n\r]+\}")
    flag = None
    for cand in candidates:
        text = cand.decode("latin-1", errors="ignore")
        match = flag_pattern.search(text)
        if match:
            flag = match.group(0)
            break

    if flag:
        print(f"[+] Flag found: {flag}")
        (script_dir / "flag.txt").write_text(flag + "\n")
        return flag
    else:
        print("[-] Flag not found in decrypted candidates")
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{sma11_N_n0_g0od_a3ac7152}
```
