import struct

with open('extracted/lib/x86_64/libhellojni.so', 'rb') as f:
    elf = f.read()

e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', elf, 0x3e)[0]
shstr_off = struct.unpack_from('<Q', elf, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]

sections = {}
for i in range(e_shnum):
    s_hdr = e_shoff + i * e_shentsize
    sh_name = struct.unpack_from('<I', elf, s_hdr)[0]
    sh_type = struct.unpack_from('<I', elf, s_hdr + 4)[0]
    sh_addr = struct.unpack_from('<Q', elf, s_hdr + 16)[0]
    sh_offset = struct.unpack_from('<Q', elf, s_hdr + 24)[0]
    sh_size = struct.unpack_from('<Q', elf, s_hdr + 32)[0]
    sh_link = struct.unpack_from('<I', elf, s_hdr + 40)[0]
    name_end = elf.find(b'\x00', shstr_off + sh_name)
    name = elf[shstr_off + sh_name : name_end].decode()
    sections[name] = {'type': sh_type, 'addr': sh_addr, 'offset': sh_offset, 'size': sh_size, 'link': sh_link}

dynsym = sections['.dynsym']
dynstr = elf[sections['.dynstr']['offset'] : sections['.dynstr']['offset'] + sections['.dynstr']['size']]

rela_plt = sections['.rela.plt']
count = rela_plt['size'] // 24
for i in range(count):
    r_offset, r_info, r_addend = struct.unpack_from('<QQq', elf, rela_plt['offset'] + i * 24)
    sym_idx = r_info >> 32
    sym_off = dynsym['offset'] + sym_idx * 24
    st_name = struct.unpack_from('<I', elf, sym_off)[0]
    name_end = dynstr.find(b'\x00', st_name)
    sym_name = dynstr[st_name : name_end].decode()
    plt_entry = 0xc20 + 0x10 * (i + 1)
    print(f"PLT[{i}] at {plt_entry:#x} -> {sym_name} (got: {r_offset:#x})")
