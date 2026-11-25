import struct

with open('unpacked/lib/x86_64/libhellojni.so', 'rb') as f:
    elf = f.read()

# Let's inspect rodata
# Find rodata section
e_shoff = struct.unpack_from('<Q', elf, 0x28)[0]
e_shentsize = struct.unpack_from('<H', elf, 0x3a)[0]
e_shnum = struct.unpack_from('<H', elf, 0x3c)[0]
e_shstrndx = struct.unpack_from('<H', elf, 0x3e)[0]
shstr_off = struct.unpack_from('<Q', elf, e_shoff + e_shstrndx * e_shentsize + 0x18)[0]

def get_shname(off):
    end = elf.find(b'\x00', shstr_off + off)
    return elf[shstr_off + off : end].decode()

rodata_sec = None
for i in range(e_shnum):
    s_hdr = elf[e_shoff + i * e_shentsize : e_shoff + (i+1) * e_shentsize]
    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack_from('<IIQQQQIIQQ', s_hdr)
    if get_shname(sh_name) == '.rodata':
        rodata_sec = (sh_addr, sh_offset, sh_size)
        break

print("rodata sec:", rodata_sec)
ro_addr, ro_off, ro_size = rodata_sec
ro_data = elf[ro_off : ro_off + ro_size]

def get_str_at_vaddr(vaddr, length=None):
    off = vaddr - ro_addr
    if length is not None:
        return ro_data[off : off + length]
    end = ro_data.find(b'\x00', off)
    return ro_data[off : end]

# Check strings loaded in chervil (0x1560)
# 0x156c: lea rdi, [rip + 0x484] -> rip is 0x1573. 0x1573 + 0x484 = 0x19f7
# 0x157c: lea rdi, [rip + 0x474] -> rip is 0x1583. 0x1583 + 0x474 = 0x19f7
# 0x158c: lea rdi, [rip + 0x464] -> rip is 0x1593. 0x1593 + 0x464 = 0x19f7
# 0x159c: lea rdi, [rip + 0x454] -> rip is 0x15a3. 0x15a3 + 0x454 = 0x19f7
print("String at 0x19f7:", get_str_at_vaddr(0x19f7))

# Format string at 0x16bb: lea rsi, [rip + 0x339] -> rip is 0x16c2. 0x16c2 + 0x339 = 0x19fb
print("Format string at 0x19fb:", get_str_at_vaddr(0x19fb))

# In pepper:
# 0x192c: lea rdi, [rip + 0x16d] -> rip is 0x1933. 0x1933 + 0x16d = 0x1aa0
# Ciphertext is at 0x1aa0, length is 0x1f (31 bytes)
cipher = get_str_at_vaddr(0x1aa0, 0x1f)
print("Pepper ciphertext (0x1aa0, 31 bytes):", cipher)

# Also check other functions:
# What strings were in rodata?
print("\nAll strings / data in rodata:")
for i in range(0, ro_size, 16):
    chunk = ro_data[i:i+16]
    ascii_chunk = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
    print(f"{ro_addr + i:04x}: {chunk.hex(' ')}  {ascii_chunk}")
