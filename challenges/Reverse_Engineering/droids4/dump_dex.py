import struct

with open('unpacked/classes.dex', 'rb') as f:
    dex = f.read()

string_ids_size, string_ids_off = struct.unpack_from('<II', dex, 0x38)
type_ids_size, type_ids_off = struct.unpack_from('<II', dex, 0x40)
proto_ids_size, proto_ids_off = struct.unpack_from('<II', dex, 0x48)
field_ids_size, field_ids_off = struct.unpack_from('<II', dex, 0x50)
method_ids_size, method_ids_off = struct.unpack_from('<II', dex, 0x58)
class_defs_size, class_defs_off = struct.unpack_from('<II', dex, 0x60)

def read_uleb128(pos):
    result = 0
    shift = 0
    while True:
        b = dex[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos

def get_string(idx):
    if idx >= string_ids_size:
        return f'<bad string idx {idx}>'
    off = struct.unpack_from('<I', dex, string_ids_off + idx * 4)[0]
    pos = off
    _, pos = read_uleb128(pos)
    end = dex.find(b'\x00', pos)
    return dex[pos:end].decode('utf-8', errors='replace')

def get_type(idx):
    if idx >= type_ids_size:
        return f'<bad type idx {idx}>'
    desc_idx = struct.unpack_from('<I', dex, type_ids_off + idx * 4)[0]
    return get_string(desc_idx)

def get_method(idx):
    if idx >= method_ids_size:
        return ('<bad method>', '<bad method>')
    class_idx, proto_idx, name_idx = struct.unpack_from('<HHI', dex, method_ids_off + idx * 8)
    return get_type(class_idx), get_string(name_idx)

def dump_class(data_off, name):
    print(f'=== CLASS {name} ===')
    pos = data_off
    sf_size, pos = read_uleb128(pos)
    if_size, pos = read_uleb128(pos)
    dm_size, pos = read_uleb128(pos)
    vm_size, pos = read_uleb128(pos)
    print(f'sf: {sf_size}, if: {if_size}, dm: {dm_size}, vm: {vm_size}')
    
    # skip fields
    for _ in range(sf_size + if_size):
        _, pos = read_uleb128(pos)
        _, pos = read_uleb128(pos)
    
    def dump_methods(count, label):
        nonlocal pos
        mid = 0
        for _ in range(count):
            diff, pos = read_uleb128(pos)
            mid += diff
            flags, pos = read_uleb128(pos)
            code_off, pos = read_uleb128(pos)
            c_name, m_name = get_method(mid)
            print(f'[{label}] {m_name} (mid={mid}, flags={flags:#x}, code_off={code_off:#x})')
            if code_off != 0:
                registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack_from('<HHHHII', dex, code_off)
                insns = dex[code_off+16 : code_off+16+insns_size*2]
                print(f'    regs: {registers_size}, insns_size: {insns_size}')
                # print instructions
                k = 0
                while k < len(insns):
                    op = insns[k]
                    # basic length table
                    if op in (0x1a,): # const-string vAA, string@BBBB (size 2 16-bit words)
                        reg = insns[k+1]
                        str_idx = struct.unpack_from('<H', insns, k+2)[0]
                        print(f'      {k//2:04x}: const-string v{reg}, \"{get_string(str_idx)}\"')
                    elif op in (0x6e, 0x6f, 0x70, 0x71, 0x72): # invoke-*
                        target_idx = struct.unpack_from('<H', insns, k+2)[0]
                        print(f'      {k//2:04x}: invoke {get_method(target_idx)}')
                    k += 2

    dump_methods(dm_size, 'direct')
    dump_methods(vm_size, 'virtual')

dump_class(0x1f322a, 'FlagstaffHill')
dump_class(0x1fb1d6, 'MainActivity')
