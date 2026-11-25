import struct

with open('extracted/classes.dex', 'rb') as f:
    dex = f.read()

string_ids_size, string_ids_off = struct.unpack_from('<II', dex, 0x38)
type_ids_size, type_ids_off = struct.unpack_from('<II', dex, 0x40)
proto_ids_size, proto_ids_off = struct.unpack_from('<II', dex, 0x48)
field_ids_size, field_ids_off = struct.unpack_from('<II', dex, 0x50)
method_ids_size, method_ids_off = struct.unpack_from('<II', dex, 0x58)

strings = []
for i in range(string_ids_size):
    off = struct.unpack_from('<I', dex, string_ids_off + i * 4)[0]
    pos = off
    while dex[pos] & 0x80:
        pos += 1
    pos += 1
    end = dex.find(b'\x00', pos)
    strings.append(dex[pos:end].decode('utf-8', errors='replace'))

types = [strings[struct.unpack_from('<I', dex, type_ids_off + i * 4)[0]] for i in range(type_ids_size)]

methods = []
for i in range(method_ids_size):
    class_idx, proto_idx, name_idx = struct.unpack_from('<HHI', dex, method_ids_off + i * 8)
    methods.append((types[class_idx], strings[name_idx]))

# Let's inspect instructions at getFlag (0x123f70) and buttonClick (0x123fdc)
for name, off in [('getFlag', 0x123f70), ('buttonClick', 0x123fdc), ('onCreate', 0x124018)]:
    registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack_from('<HHHHII', dex, off)
    insns = dex[off+16 : off+16+insns_size*2]
    print(f'=== {name} ===')
    words = struct.unpack(f'<{insns_size}H', insns)
    pc = 0
    while pc < insns_size:
        w = words[pc]
        op = w & 0xff
        b = (w >> 8) & 0xff
        print(f'  {pc:04x}: {w:04x} op={op:#04x}', end=' ')
        if op == 0x1a:
            str_idx = words[pc+1]
            print(f'const-string v{b}, "{strings[str_idx]}"')
            pc += 2
        elif op == 0x1b:
            str_idx = words[pc+1] | (words[pc+2] << 16)
            print(f'const-string/jumbo v{b}, "{strings[str_idx]}"')
            pc += 3
        elif op == 0x12:
            print(f'const/4 v{b & 0xf}, {b >> 4}')
            pc += 1
        elif op == 0x13:
            val = struct.unpack('<h', struct.pack('<H', words[pc+1]))[0]
            print(f'const/16 v{b}, {val} ({val:#x})')
            pc += 2
        elif op == 0x14:
            val = struct.unpack('<i', struct.pack('<I', words[pc+1] | (words[pc+2] << 16)))[0]
            print(f'const v{b}, {val} ({val:#x})')
            pc += 3
        elif 0x6e <= op <= 0x72:
            meth_idx = words[pc+1]
            print(f'invoke op={op:#x} args_info={b:#x} meth={methods[meth_idx]}')
            pc += 3
        elif 0x74 <= op <= 0x78:
            meth_idx = words[pc+1]
            print(f'invoke-range op={op:#x} meth={methods[meth_idx]}')
            pc += 3
        elif 0x52 <= op <= 0x6d:
            field_idx = words[pc+1]
            print(f'field op={op:#x} field_idx={field_idx}')
            pc += 2
        elif 0x28 <= op <= 0x2a: # goto
            print(f'goto op={op:#x}')
            pc += (op - 0x27)
        elif 0x32 <= op <= 0x3d: # if-test
            print(f'if op={op:#x} v{b & 0xf}, v{b >> 4}, target={pc + struct.unpack("<h", struct.pack("<H", words[pc+1]))[0]}')
            pc += 2
        elif op in (0x0e, 0x0f, 0x10, 0x11): # return
            print(f'return op={op:#x}')
            pc += 1
        else:
            print(f'raw {words[pc:pc+2]}')
            pc += 1
