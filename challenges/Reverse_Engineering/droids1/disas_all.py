import struct
import capstone

with open('extracted/lib/x86_64/libhellojni.so', 'rb') as f:
    elf = f.read()

# Parse ELF64
e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', elf, 0x3e)[0]

shstr_off = struct.unpack_from('<Q', elf, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]

sections = []
for i in range(e_shnum):
    s_hdr = e_shoff + i * e_shentsize
    sh_name = struct.unpack_from('<I', elf, s_hdr)[0]
    sh_type = struct.unpack_from('<I', elf, s_hdr + 4)[0]
    sh_flags = struct.unpack_from('<Q', elf, s_hdr + 8)[0]
    sh_addr = struct.unpack_from('<Q', elf, s_hdr + 16)[0]
    sh_offset = struct.unpack_from('<Q', elf, s_hdr + 24)[0]
    sh_size = struct.unpack_from('<Q', elf, s_hdr + 32)[0]
    sh_link = struct.unpack_from('<I', elf, s_hdr + 40)[0]
    sh_info = struct.unpack_from('<I', elf, s_hdr + 44)[0]
    name_end = elf.find(b'\x00', shstr_off + sh_name)
    name = elf[shstr_off + sh_name : name_end].decode()
    sections.append({
        'name': name, 'type': sh_type, 'addr': sh_addr, 'offset': sh_offset,
        'size': sh_size, 'link': sh_link, 'info': sh_info
    })

dynsym = next(s for s in sections if s['name'] == '.dynsym')
dynstr = sections[dynsym['link']]
dynstr_data = elf[dynstr['offset'] : dynstr['offset'] + dynstr['size']]

sym_count = dynsym['size'] // 24
symbols = {}
addr_to_sym = {}
for i in range(sym_count):
    sym_off = dynsym['offset'] + i * 24
    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from('<IBBHQQ', elf, sym_off)
    name_end = dynstr_data.find(b'\x00', st_name)
    sym_name = dynstr_data[st_name : name_end].decode()
    if st_value != 0:
        symbols[sym_name] = (st_value, st_size)
        addr_to_sym[st_value] = sym_name

# Rela.plt to find PLT targets
rela_plt = next(s for s in sections if s['name'] == '.rela.plt')
plt = next(s for s in sections if s['name'] == '.plt')
print(f"PLT at {plt['addr']:#x}, size {plt['size']:#x}")

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

# Let's inspect .plt
for ins in md.disasm(elf[plt['offset'] : plt['offset'] + plt['size']], plt['addr']):
    print(f"  0x{ins.address:x}: {ins.mnemonic}\t{ins.op_str}")

# Disassemble all functions in symbols
for name, (addr, size) in sorted(symbols.items(), key=lambda x: x[1][0]):
    print(f"\n==================== {name} (0x{addr:x}, size {size}) ====================")
    code = elf[addr : addr + (size if size > 0 else 100)]
    for ins in md.disasm(code, addr):
        print(f"  0x{ins.address:x}: {ins.mnemonic}\t{ins.op_str}")
