import capstone
import struct

with open('unpacked/lib/x86_64/libhellojni.so', 'rb') as f:
    elf = f.read()

# Parse sections
e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', elf, 0x3e)[0]
shstr_off = struct.unpack_from('<Q', elf, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]

def get_shname(off):
    end = elf.find(b'\x00', shstr_off + off)
    return elf[shstr_off + off : end].decode()

sections = {}
for i in range(e_shnum):
    s_hdr = elf[e_shoff + i * e_shentsize : e_shoff + (i+1) * e_shentsize]
    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from('<IIQQQQIIQQ', s_hdr)
    sname = get_shname(sh_name)
    sections[sname] = {
        'addr': sh_addr,
        'offset': sh_offset,
        'size': sh_size,
        'entsize': sh_entsize,
        'link': sh_link
    }

# Read dynsym
dynsym = sections['.dynsym']
dynstr = sections['.dynstr']
dynstr_data = elf[dynstr['offset'] : dynstr['offset'] + dynstr['size']]
def get_dynstr(off):
    end = dynstr_data.find(b'\x00', off)
    return dynstr_data[off:end].decode()

# Read relocations for PLT (.rela.plt)
rela_plt = sections['.rela.plt']
num_relas = rela_plt['size'] // rela_plt['entsize']
plt_map = {} # plt addr -> symbol name
plt_sec = sections['.plt']

# In x86_64 ELF: first PLT entry is 0x10 bytes, then each entry is 0x10 bytes
for i in range(num_relas):
    r_off, r_info, r_addend = struct.unpack_from('<QQq', elf, rela_plt['offset'] + i * rela_plt['entsize'])
    sym_idx = r_info >> 32
    sym_hdr = elf[dynsym['offset'] + sym_idx * dynsym['entsize'] : dynsym['offset'] + (sym_idx+1) * dynsym['entsize']]
    st_name = struct.unpack_from('<I', sym_hdr)[0]
    sym_name = get_dynstr(st_name)
    plt_entry_addr = plt_sec['addr'] + 0x10 + i * 0x10
    plt_map[plt_entry_addr] = sym_name
    print(f"PLT 0x{plt_entry_addr:x} -> {sym_name}")

# Also find all symbols in dynsym
symbols = {}
num_syms = dynsym['size'] // dynsym['entsize']
for i in range(num_syms):
    sym_hdr = elf[dynsym['offset'] + i * dynsym['entsize'] : dynsym['offset'] + (i+1) * dynsym['entsize']]
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', sym_hdr)
    name = get_dynstr(st_name)
    if name and st_value != 0:
        symbols[st_value] = name

# Disassemble entire .text
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
text_sec = sections['.text']
code = elf[text_sec['offset'] : text_sec['offset'] + text_sec['size']]

print("\n--- TEXT DISASSEMBLY ---")
for insn in md.disasm(code, text_sec['addr']):
    if insn.address in symbols:
        print(f"\n<{symbols[insn.address]}>:")
    comment = ""
    # resolve call target if in plt or symbols
    if insn.mnemonic == 'call':
        try:
            target = int(insn.op_str, 16)
            if target in plt_map:
                comment = f" ; {plt_map[target]}"
            elif target in symbols:
                comment = f" ; {symbols[target]}"
        except:
            pass
    elif 'rip +' in insn.op_str or 'rip -' in insn.op_str:
        # compute rip relative address
        parts = insn.op_str.split('rip ')
        sign = parts[1][0]
        offset_hex = parts[1][2:].split(']')[0]
        offset = int(offset_hex, 16)
        target = insn.address + insn.size + (offset if sign == '+' else -offset)
        # check if in rodata
        rodata = sections['.rodata']
        if rodata['addr'] <= target < rodata['addr'] + rodata['size']:
            str_data = elf[rodata['offset'] + (target - rodata['addr']):]
            end_s = str_data.find(b'\x00')
            comment = f" ; rodata[{target:#x}]: {str_data[:end_s]}"
        elif target in symbols:
            comment = f" ; {symbols[target]}"
    print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}{comment}")
