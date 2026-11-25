#!/usr/bin/env python3
"""
Solve script for GDB baby step 4 (#398)
Category: Reverse Engineering
"""
import os
import struct
from pathlib import Path

def parse_connection_cfg(cfg_path="connection.cfg"):
    cfg = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line:
                    key, val = line.split("=", 1)
                    cfg[key.strip()] = val.strip()
    return cfg

def extract_constant_from_binary(binary_path="debugger0_d"):
    with open(binary_path, "rb") as f:
        data = f.read()

    # Parse ELF64 header
    e_shoff = struct.unpack("<Q", data[40:48])[0]
    e_shentsize = struct.unpack("<H", data[58:60])[0]
    e_shnum = struct.unpack("<H", data[60:62])[0]
    e_shstrndx = struct.unpack("<H", data[62:64])[0]

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack("<IIQQQQIIQQ", data[off:off+64])
        sections.append({
            "idx": i, "name_idx": sh_name, "type": sh_type, "flags": sh_flags,
            "addr": sh_addr, "offset": sh_offset, "size": sh_size, "link": sh_link, "info": sh_info,
            "entsize": sh_entsize
        })

    shstrtab = data[sections[e_shstrndx]["offset"] : sections[e_shstrndx]["offset"] + sections[e_shstrndx]["size"]]
    symtab_sec = None
    strtab_sec = None

    for s in sections:
        name = shstrtab[s["name_idx"]:].split(b"\x00", 1)[0].decode("latin1")
        s["name"] = name
        if s["type"] == 2:  # SHT_SYMTAB
            symtab_sec = s
        elif name == ".strtab":
            strtab_sec = s

    func1_addr = None
    func1_size = 0
    if symtab_sec and strtab_sec:
        symdata = data[symtab_sec["offset"] : symtab_sec["offset"] + symtab_sec["size"]]
        strdata = data[strtab_sec["offset"] : strtab_sec["offset"] + strtab_sec["size"]]
        entsize = symtab_sec["entsize"] if symtab_sec["entsize"] else 24
        num_syms = len(symdata) // entsize
        for i in range(num_syms):
            sy = symdata[i*entsize : (i+1)*entsize]
            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack("<IBBHQQ", sy)
            sym_name = strdata[st_name:].split(b"\x00", 1)[0].decode("latin1")
            if sym_name == "func1":
                func1_addr = st_value
                func1_size = st_size
                break

    # Calculate file offset for func1
    func1_offset = None
    for s in sections:
        if s["addr"] <= func1_addr < s["addr"] + s["size"]:
            func1_offset = s["offset"] + (func1_addr - s["addr"])
            break

    if func1_offset is None:
        raise ValueError(f"Could not resolve file offset for func1 at {hex(func1_addr)}")

    func1_bytes = data[func1_offset : func1_offset + func1_size]
    print(f"[*] func1 at {hex(func1_addr)} (offset {hex(func1_offset)}): {func1_bytes.hex(' ')}", flush=True)

    # Find imul eax, eax, imm32: opcode 0x69 0xc0 <4-byte imm>
    imul_idx = func1_bytes.find(b"\x69\xc0")
    if imul_idx == -1:
        raise ValueError("Could not find imul opcode (69 c0) in func1")

    imm_bytes = func1_bytes[imul_idx + 2 : imul_idx + 6]
    constant = struct.unpack("<I", imm_bytes)[0]
    return constant

def solve():
    print("[*] Solving GDB baby step 4...", flush=True)
    cfg = parse_connection_cfg("connection.cfg")
    print(f"[*] Configuration: {cfg}", flush=True)

    constant = extract_constant_from_binary("debugger0_d")
    print(f"[*] Extracted constant: hex={hex(constant)}, decimal={constant}", flush=True)

    flag = f"academy{{{constant}}}"
    
    # Validation against decoy patterns
    for bad in ["fake", "decoy", "honey", "not_the_flag", "dummy"]:
        if bad in flag.lower():
            raise ValueError(f"Decoy flag detected: {flag}")

    print(f"[+] Found Flag: {flag}", flush=True)

    flag_path = Path("flag.txt")
    flag_path.write_text(flag, encoding="utf-8")
    print(f"[*] Saved flag to {flag_path.resolve()}", flush=True)

    return flag

if __name__ == "__main__":
    solve()
