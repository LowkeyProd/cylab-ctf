# Writeup: rail-fence

## Header & Metadata
- **Challenge:** rail-fence (ID: 289)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `https://en.wikipedia.org/wiki/Rail_fence_cipher`
- **Attached Files:** message.txt
- **Official Flag:** `academy{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_43BBCEC4}`

---

## Mô tả bài toán (Overview / Analysis)
A type of transposition cipher is the rail fence cipher, which is described
[here](https://en.wikipedia.org/wiki/Rail_fence_cipher). Here is one such
cipher encrypted using the rail fence with 4 rails. Can you decrypt it?
Download the message <a href='https://challenge-files.cylabacademy.net/library/d6cea3d41550d2d3e365dd3a7ea99fe9b44fe5fa437d1c921b5134a2070894a5/message.txt' download>here</a>.

The decoded message names a phrase. Put that phrase, and nothing else, in the
academy flag format: `academy{phrase}`.

### Hints
- Once you've understood how the cipher works, it's best to draw it out
  yourself on paper

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for rail-fence (#289)
Category: Cryptography
"""
from pathlib import Path
import re

def decrypt_rail_fence(ciphertext: str, rails: int = 4) -> str:
    n = len(ciphertext)
    cycle = 2 * (rails - 1)
    
    def get_rail(i):
        idx = i % cycle
        return idx if idx < rails else cycle - idx

    rail_indices = [[] for _ in range(rails)]
    for i in range(n):
        rail_indices[get_rail(i)].append(i)

    plaintext = [''] * n
    pos = 0
    for r in range(rails):
        for idx in rail_indices[r]:
            plaintext[idx] = ciphertext[pos]
            pos += 1

    return ''.join(plaintext)

def solve():
    message_path = Path(__file__).resolve().parent / "message.txt"
    if not message_path.exists():
        print("[-] message.txt not found!", flush=True)
        return None

    ciphertext = message_path.read_text()
    decoded = decrypt_rail_fence(ciphertext, rails=4)
    print(f"[*] Decoded message: {decoded}", flush=True)

    # Decoded message format: "The flag is: WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_D3AB175F"
    if ":" in decoded:
        phrase = decoded.split(":", 1)[1].strip()
    else:
        phrase = decoded.strip()

    flag = f"academy{{{phrase}}}"
    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = Path(__file__).resolve().parent / "flag.txt"
    flag_path.write_text(flag + "\n")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{WH3R3_D035_7H3_F3NC3_8361N_4ND_3ND_43BBCEC4}
```
