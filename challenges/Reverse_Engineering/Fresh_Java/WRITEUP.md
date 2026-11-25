# Writeup: Fresh Java

## Header & Metadata
- **Challenge:** Fresh Java (ID: 271)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** KeygenMe.class
- **Official Flag:** `academy{700l1ng_r3qu1r3d_5e462060}`

---

## Mô tả bài toán (Overview / Analysis)
Can you get the flag?
Reverse engineer this <a href='https://challenge-files.cylabacademy.net/library/8a49236ebd176634e844de1f01d33adf9d0185836ef578fd72b168e513a4eabc/KeygenMe.class' download>Java program</a>.

### Hints
- Use a decompiler for Java!

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Fresh Java (#271)
Category: Reverse Engineering
"""
import sys
import struct
from pathlib import Path

def parse_class_for_flag(class_path: Path) -> str:
    with open(class_path, 'rb') as f:
        data = f.read()

    pos = 0
    magic, minor, major = struct.unpack_from('>IHH', data, pos)
    pos += 8
    cp_count = struct.unpack_from('>H', data, pos)[0]
    pos += 2

    cp = [None] * cp_count
    idx = 1
    while idx < cp_count:
        tag = data[pos]
        pos += 1
        if tag == 7: # Class
            name_idx = struct.unpack_from('>H', data, pos)[0]
            pos += 2
            cp[idx] = ('Class', name_idx)
        elif tag in (9, 10, 11): # Fieldref, Methodref, InterfaceMethodref
            class_idx, nt_idx = struct.unpack_from('>HH', data, pos)
            pos += 4
            cp[idx] = ('Ref', tag, class_idx, nt_idx)
        elif tag == 8: # String
            str_idx = struct.unpack_from('>H', data, pos)[0]
            pos += 2
            cp[idx] = ('String', str_idx)
        elif tag in (3, 4): # Integer, Float
            val = struct.unpack_from('>I', data, pos)[0]
            pos += 4
            cp[idx] = ('Int/Float', val)
        elif tag in (5, 6): # Long, Double
            val = struct.unpack_from('>Q', data, pos)[0]
            pos += 8
            cp[idx] = ('Long/Double', val)
            idx += 1
        elif tag == 12: # NameAndType
            n_idx, d_idx = struct.unpack_from('>HH', data, pos)
            pos += 4
            cp[idx] = ('NameAndType', n_idx, d_idx)
        elif tag == 1: # Utf8
            length = struct.unpack_from('>H', data, pos)[0]
            pos += 2
            s = data[pos:pos+length]
            pos += length
            cp[idx] = ('Utf8', s)
        elif tag in (15, 16, 18): # MethodHandle, MethodType, InvokeDynamic
            pos += 3 if tag == 15 else 4
            cp[idx] = ('Other', tag)
        else:
            raise ValueError(f'Unknown tag {tag} at {pos}')
        idx += 1

    access_flags, this_c, super_c, if_count = struct.unpack_from('>HHHH', data, pos)
    pos += 8 + if_count * 2

    fields_count = struct.unpack_from('>H', data, pos)[0]
    pos += 2
    for _ in range(fields_count):
        pos += 6
        ac = struct.unpack_from('>H', data, pos)[0]
        pos += 2
        for _ in range(ac):
            name_idx, attr_len = struct.unpack_from('>HI', data, pos)
            pos += 6 + attr_len

    methods_count = struct.unpack_from('>H', data, pos)[0]
    pos += 2
    code_bytes = b''
    for _ in range(methods_count):
        m_acc, m_name, m_desc, m_ac = struct.unpack_from('>HHHH', data, pos)
        pos += 8
        m_name_str = cp[m_name][1]
        for _ in range(m_ac):
            attr_name_idx, attr_len = struct.unpack_from('>HI', data, pos)
            pos += 6
            attr_name = cp[attr_name_idx][1]
            attr_data = data[pos:pos+attr_len]
            pos += attr_len
            if m_name_str == b'main' and attr_name == b'Code':
                max_stack, max_locals, code_len = struct.unpack_from('>HHI', attr_data, 0)
                code_bytes = attr_data[8:8+code_len]

    if not code_bytes:
        raise ValueError("Could not find main method code attribute")

    # Extract charAt comparison constants
    chars = {}
    i = 0
    while i < len(code_bytes):
        if code_bytes[i] == 0x2c: # aload_2
            i += 1
            if i >= len(code_bytes):
                break
            idx = None
            if 0x03 <= code_bytes[i] <= 0x08:
                idx = code_bytes[i] - 0x03
                i += 1
            elif code_bytes[i] == 0x10:
                idx = code_bytes[i+1]
                i += 2
            else:
                continue

            # Check for invokevirtual charAt (0xb6)
            if i + 3 <= len(code_bytes) and code_bytes[i] == 0xb6:
                i += 3
                if i + 2 <= len(code_bytes) and code_bytes[i] == 0x10:
                    expected_char = chr(code_bytes[i+1])
                    chars[idx] = expected_char
                    i += 2
        else:
            i += 1

    if not chars:
        raise ValueError("Failed to extract characters from bytecode")

    flag = ''.join(chars[i] for i in range(len(chars)))
    return flag

def solve():
    base_dir = Path(__file__).resolve().parent
    cfg_file = base_dir / "connection.cfg"

    config = {}
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if '=' in line:
                k, v = line.strip().split('=', 1)
                config[k] = v

    class_file = base_dir / "KeygenMe.class"
    if not class_file.exists():
        url = config.get("URL")
        if url:
            import requests
            print(f"[*] Downloading KeygenMe.class from {url}...", flush=True)
            r = requests.get(url, timeout=10)
            class_file.write_bytes(r.content)
        else:
            print("[-] KeygenMe.class not found and no URL configured.", flush=True)
            return None

    print(f"[*] Analyzing {class_file.name}...", flush=True)
    flag = parse_class_for_flag(class_file)
    print(f"[+] Flag found: {flag}", flush=True)

    flag_file = base_dir / "flag.txt"
    flag_file.write_text(flag.strip() + "\n")
    print(f"[+] Saved flag to {flag_file}", flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{700l1ng_r3qu1r3d_5e462060}
```
