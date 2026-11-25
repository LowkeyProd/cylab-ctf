#!/usr/bin/env python3
"""
Solve script for ASCII FTW (#389)
Category: Reverse Engineering
"""
import struct
from pathlib import Path
import capstone

def solve():
    print("[*] Solving ASCII FTW...", flush=True)
    binary_path = Path(__file__).parent / "asciiftw"
    
    with open(binary_path, "rb") as f:
        data = f.read()

    # Parse ELF to find .text and symbol table
    e_shoff = struct.unpack('<Q', data[40:48])[0]
    e_shentsize = struct.unpack('<H', data[58:60])[0]
    e_shnum = struct.unpack('<H', data[60:62])[0]
    e_shstrndx = struct.unpack('<H', data[62:64])[0]

    shstr_hdr = data[e_shoff + e_shstrndx * e_shentsize : e_shoff + (e_shstrndx + 1) * e_shentsize]
    shstr_offset = struct.unpack('<Q', shstr_hdr[24:32])[0]

    sections = {}
    for i in range(e_shnum):
        sh = data[e_shoff + i * e_shentsize : e_shoff + (i + 1) * e_shentsize]
        sh_name_idx = struct.unpack('<I', sh[0:4])[0]
        sh_type = struct.unpack('<I', sh[4:8])[0]
        sh_addr = struct.unpack('<Q', sh[16:24])[0]
        sh_offset = struct.unpack('<Q', sh[24:32])[0]
        sh_size = struct.unpack('<Q', sh[32:40])[0]
        sh_entsize = struct.unpack('<Q', sh[56:64])[0]
        name_end = data.find(b'\x00', shstr_offset + sh_name_idx)
        name = data[shstr_offset + sh_name_idx : name_end].decode('ascii', errors='ignore')
        sections[name] = (sh_type, sh_addr, sh_offset, sh_size, sh_entsize)

    symtab_info = sections['.symtab']
    strtab_info = sections['.strtab']

    symtab_data = data[symtab_info[2] : symtab_info[2] + symtab_info[3]]
    strtab_data = data[strtab_info[2] : strtab_info[2] + strtab_info[3]]

    main_val, main_size = 0, 0
    for i in range(0, len(symtab_data), 24):
        st_name = struct.unpack('<I', symtab_data[i:i+4])[0]
        st_value = struct.unpack('<Q', symtab_data[i+8:i+16])[0]
        st_size = struct.unpack('<Q', symtab_data[i+16:i+24])[0]
        name_end = strtab_data.find(b'\x00', st_name)
        sname = strtab_data[st_name : name_end].decode('ascii', errors='ignore')
        if sname == "main":
            main_val, main_size = st_value, st_size
            break

    text_info = sections['.text']
    offset_in_text = main_val - text_info[1]
    main_code = data[text_info[2] + offset_in_text : text_info[2] + offset_in_text + main_size]

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    # Map stack offset to byte value
    # Looking for: mov byte ptr [rbp - off], imm
    stack_bytes = {}
    for insn in md.disasm(main_code, main_val):
        # Check for mov byte ptr [rbp - offset], val
        # opcode C6 45 <disp> <imm>
        if insn.mnemonic == 'mov' and 'byte ptr [rbp -' in insn.op_str:
            parts = insn.op_str.split(',')
            dst = parts[0].strip()
            imm_str = parts[1].strip()
            imm = int(imm_str, 16) if imm_str.startswith('0x') else int(imm_str)
            
            # extract offset: e.g. byte ptr [rbp - 0x30]
            offset_part = dst.split('-')[1].rstrip(']').strip()
            offset = int(offset_part, 16) if offset_part.startswith('0x') else int(offset_part)
            stack_bytes[offset] = imm

    # Reconstruct string in order of increasing memory address (rbp - 0x30, rbp - 0x2f, ...)
    sorted_offsets = sorted(stack_bytes.keys(), reverse=True)
    flag_bytes = bytes([stack_bytes[off] for off in sorted_offsets])
    flag = flag_bytes.decode('ascii')

    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag.strip() + "\n")
    print(f"[+] Saved flag to {flag_path}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
