#!/usr/bin/env python3
"""
Solver for asm2 (Reverse Engineering)
Simulates the execution of the assembly function asm2 from test.S.
"""

import os
import re
import json
from pathlib import Path


def parse_asm2_from_file(filepath: Path):
    """
    Parses test.S to extract constants used in asm2.
    """
    if not filepath.exists():
        # Fallback constants if test.S is missing
        return 0x1, 0xE7, 0x5ED6

    content = filepath.read_text(encoding="utf-8")

    inc_v4_match = re.search(
        r"add\s+DWORD PTR \[ebp-0x4\],\s*(0x[0-9a-fA-F]+|\d+)", content
    )
    inc_v8_match = re.search(
        r"add\s+DWORD PTR \[ebp-0x8\],\s*(0x[0-9a-fA-F]+|\d+)", content
    )
    cmp_v8_match = re.search(
        r"cmp\s+DWORD PTR \[ebp-0x8\],\s*(0x[0-9a-fA-F]+|\d+)", content
    )

    inc_v4 = int(inc_v4_match.group(1), 0) if inc_v4_match else 0x1
    inc_v8 = int(inc_v8_match.group(1), 0) if inc_v8_match else 0xE7
    cmp_v8 = int(cmp_v8_match.group(1), 0) if cmp_v8_match else 0x5ED6

    return inc_v4, inc_v8, cmp_v8


def get_call_args(base_dir: Path):
    """
    Extracts function arguments asm2(arg1, arg2) from info.json or README.md.
    Defaults to (0xb, 0x1a).
    """
    info_path = base_dir / "info.json"
    if info_path.exists():
        try:
            with open(info_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                desc = data.get("description", "")
                m = re.search(r"asm2\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)", desc)
                if m:
                    return int(m.group(1), 0), int(m.group(2), 0)
        except Exception:
            pass
    return 0xB, 0x1A


def simulate_asm2(arg1: int, arg2: int, inc_v4: int = 0x1, inc_v8: int = 0xE7, cmp_v8: int = 0x5ED6) -> int:
    """
    Simulates the assembly logic:
        <+0>: push ebp
        <+1>: mov ebp, esp
        <+3>: sub esp, 0x10
        <+6>: mov eax, DWORD PTR [ebp+0xc]   ; eax = arg2
        <+9>: mov DWORD PTR [ebp-0x4], eax   ; var_4 = arg2
        <+12>: mov eax, DWORD PTR [ebp+0x8]  ; eax = arg1
        <+15>: mov DWORD PTR [ebp-0x8], eax  ; var_8 = arg1
        <+18>: jmp <asm2+31>
        <+20>: add DWORD PTR [ebp-0x4], inc_v4
        <+24>: add DWORD PTR [ebp-0x8], inc_v8
        <+31>: cmp DWORD PTR [ebp-0x8], cmp_v8
        <+38>: jle <asm2+20>
        <+40>: mov eax, DWORD PTR [ebp-0x4]
        <+43>: leave
        <+44>: ret
    """
    var_4 = arg2 & 0xFFFFFFFF
    var_8 = arg1 & 0xFFFFFFFF

    # Jump to cmp first
    while var_8 <= cmp_v8:
        var_4 = (var_4 + inc_v4) & 0xFFFFFFFF
        var_8 = (var_8 + inc_v8) & 0xFFFFFFFF

    return var_4


def solve():
    script_dir = Path(__file__).parent.resolve()
    test_asm_file = script_dir / "test.S"

    # 1. Read input data
    inc_v4, inc_v8, cmp_v8 = parse_asm2_from_file(test_asm_file)
    arg1, arg2 = get_call_args(script_dir)

    # 2. Perform transformations / emulation
    result = simulate_asm2(arg1, arg2, inc_v4, inc_v8, cmp_v8)
    token = hex(result)

    # 3. Print decoded token
    print(token)

    # 4. Save flag.txt
    flag_file = script_dir / "flag.txt"
    with open(flag_file, "w", encoding="utf-8") as f:
        f.write(token.strip())

    return token


if __name__ == "__main__":
    solve()
