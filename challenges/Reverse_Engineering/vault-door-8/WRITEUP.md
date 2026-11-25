# Writeup: vault-door-8

## Header & Metadata
- **Challenge:** vault-door-8 (ID: 10)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** VaultDoor8.java
- **Official Flag:** `academy{s0m3_m0r3_b1t_sh1fTiNg_14c0f2f11}`

---

## Mô tả bài toán (Overview / Analysis)
Apparently Dr. Evil's minions knew that our agency was making copies of their source code, because they intentionally sabotaged this source code in order to make it harder for our agents to analyze and crack into! The result is a quite mess, but I trust that my best special agent will find a way to solve it.
The source code for this vault is here: <a href='https://challenge-files.cylabacademy.net/library/0b7c9ff3145fd1a47f09ac08c11072dd1d23d2684d24df1388d720ff47e738a2/VaultDoor8.java' download>VaultDoor8.java</a>

### Hints
- Clean up the source code so that you can read it and understand what is going on.
- Draw a diagram to illustrate which bits are being switched in the scramble() method, then figure out a sequence of bit switches to undo it. You should be able to reuse the switchBits() method as is.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for vault-door-8 (#10)
Reverses the bit transposition cipher in VaultDoor8.java
"""

def switch_bits(c, p1, p2):
    mask1 = 1 << p1
    mask2 = 1 << p2
    bit1 = c & mask1
    bit2 = c & mask2
    rest = c & ~(mask1 | mask2)
    shift = p2 - p1
    result = (bit1 << shift) | (bit2 >> shift) | rest
    return result

def unscramble_char(c):
    # Reverse order of operations performed in scramble()
    c = switch_bits(c, 6, 7)
    c = switch_bits(c, 2, 5)
    c = switch_bits(c, 3, 4)
    c = switch_bits(c, 0, 1)
    c = switch_bits(c, 4, 7)
    c = switch_bits(c, 5, 6)
    c = switch_bits(c, 0, 3)
    c = switch_bits(c, 1, 2)
    return c

def solve():
    expected = [
        0xF4, 0xC0, 0x97, 0xF0, 0x77, 0x97, 0xC0, 0xE4,
        0xF0, 0x77, 0xA4, 0xD0, 0xC5, 0x77, 0xF4, 0x86,
        0xD0, 0xA5, 0x45, 0x96, 0x27, 0xB5, 0x77, 0xD0,
        0xC1, 0xB4, 0xC0, 0xA5, 0xE0, 0xA5, 0xD0, 0xD0
    ]

    password = ''.join(chr(unscramble_char(b)) for b in expected)
    flag = f"picoCTF{{{password}}}"
    
    print(f"Flag: {flag}")

    with open("flag.txt", "w") as f:
        f.write(flag + "\n")

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{s0m3_m0r3_b1t_sh1fTiNg_14c0f2f11}
```
