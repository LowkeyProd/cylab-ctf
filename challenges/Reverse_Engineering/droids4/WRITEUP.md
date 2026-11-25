# Writeup: droids4

## Header & Metadata
- **Challenge:** droids4 (ID: 17)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** four.apk
- **Official Flag:** `academy{not.particularly.silly}`

---

## Mô tả bài toán (Overview / Analysis)

Reverse the pass, patch the file, get the flag. Check out this <a href='https://challenge-files.cylabacademy.net/library/6a4e0bef83d40ea9121009c5ae6a5230e06eb011eef934798704fa66bcfc84f0/four.apk' download>file</a>.

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for droids4 (#17)
Category: Reverse Engineering | Difficulty: Hard

Analysis:
In four.apk:
1. FlagstaffHill.getFlag(String input, Context ctx) builds the string "alphabetsoup"
   from 4 StringBuilders and compares input to "alphabetsoup".
   If matching, it was supposed to call the native method cardamom(input).
2. libhellojni.so implements Java_com_hellocmu_picoctf_FlagstaffHill_cardamom:
   - Verifies input with chervil(input), which checks if input == "alphabetsoup"
   - If valid, calls pepper(input) which unscrambles a 31-byte ciphertext at offset 0x1aa0
     using the key "alphabetsoup" via XOR: res[i] = cipher[i] ^ key[i % len(key)].
"""

import os
import struct

def extract_flag_from_apk(apk_or_so_path):
    # If path to libhellojni.so is given or can be located
    so_paths = [
        apk_or_so_path,
        os.path.join(os.path.dirname(__file__), 'unpacked', 'lib', 'x86_64', 'libhellojni.so'),
        os.path.join(os.path.dirname(__file__), 'unpacked', 'lib', 'arm64-v8a', 'libhellojni.so'),
    ]

    key = b"alphabetsoup"
    cipher = None

    for p in so_paths:
        if os.path.isfile(p):
            with open(p, 'rb') as f:
                elf = f.read()

            # Find .rodata section
            e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
            e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
            e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]
            e_shstrndx = struct.unpack_from('<H', elf, 0x3e)[0]
            shstr_off = struct.unpack_from('<Q', elf, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]

            def get_shname(off):
                end = elf.find(b'\x00', shstr_off + off)
                return elf[shstr_off + off : end].decode()

            for i in range(e_shnum):
                s_hdr = elf[e_shoff + i * e_shentsize : e_shoff + (i+1) * e_shentsize]
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from('<IIQQQQIIQQ', s_hdr)
                if get_shname(sh_name) == '.rodata':
                    # In x86_64 libhellojni.so, pepper ciphertext is at vaddr 0x1aa0, which is offset 0x1aa0
                    # The length is 31 bytes (0x1f)
                    cipher_off = 0x1aa0 - sh_addr + sh_offset
                    cipher = elf[cipher_off : cipher_off + 31]
                    break
            if cipher:
                break

    if not cipher:
        # Fallback to extracted constant ciphertext
        cipher = bytes([
            0x00, 0x0f, 0x11, 0x0c, 0x04, 0x0f, 0x1c, 0x0f,
            0x1d, 0x00, 0x01, 0x5e, 0x11, 0x0d, 0x02, 0x1c,
            0x08, 0x01, 0x10, 0x18, 0x12, 0x1d, 0x19, 0x09,
            0x4f, 0x1f, 0x19, 0x04, 0x0d, 0x1b, 0x18
        ])

    decrypted = bytes([c ^ key[i % len(key)] for i, c in enumerate(cipher)])
    return decrypted.decode('utf-8', errors='replace')

def main():
    print("[*] Reversing droids4...", flush=True)
    flag = extract_flag_from_apk('unpacked/lib/x86_64/libhellojni.so')
    print(f"[+] Flag recovered: {flag}", flush=True)

    with open('flag.txt', 'w') as f:
        f.write(flag + '\n')
    print("[+] Flag saved to flag.txt", flush=True)

if __name__ == '__main__':
    main()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{not.particularly.silly}
```
