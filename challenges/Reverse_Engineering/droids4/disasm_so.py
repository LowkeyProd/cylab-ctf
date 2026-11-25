import capstone
import struct

with open('unpacked/lib/x86_64/libhellojni.so', 'rb') as f:
    elf = f.read()

# ELF64 header
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

print("Sections found:", list(sections.keys()))

# Read dynsym
dynsym = sections['.dynsym']
dynstr = sections['.dynstr']
dynstr_data = elf[dynstr['offset'] : dynstr['offset'] + dynstr['size']]

def get_dynstr(off):
    end = dynstr_data.find(b'\x00', off)
    return dynstr_data[off:end].decode()

symbols = {}
num_syms = dynsym['size'] // dynsym['entsize']
for i in range(num_syms):
    sym_hdr = elf[dynsym['offset'] + i * dynsym['entsize'] : dynsym['offset'] + (i+1) * dynsym['entsize']]
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', sym_hdr)
    name = get_dynstr(st_name)
    if name:
        symbols[name] = (st_value, st_size)

for sym, (val, size) in symbols.items():
    if 'cardamom' in sym or 'Java' in sym or 'unscramble' in sym or 'getResponse' in sym:
        print(f"Symbol {sym}: value={val:#x}, size={size:#x}")

# Disassemble cardamom
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

for sym in ['Java_com_hellocmu_picoctf_FlagstaffHill_cardamom', 'cardamom', 'unscramble', 'getResponse']:
    if sym in symbols:
        val, size = symbols[sym]
        text_sec = sections['.text']
        file_off = val - text_sec['addr'] + text_sec['offset']
        code = elf[file_off : file_off + (size if size > 0 else 0x100)]
        print(f"\n=== Disassembly of {sym} ({val:#x}) ===")
        for insn in md.disasm(code, val):
            print(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
