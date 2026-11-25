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
