import struct

with open('unpacked/classes.dex', 'rb') as f:
    dex = f.read()

string_ids_size, string_ids_off = struct.unpack_from('<II', dex, 0x38)
type_ids_size, type_ids_off = struct.unpack_from('<II', dex, 0x40)
proto_ids_size, proto_ids_off = struct.unpack_from('<II', dex, 0x48)
field_ids_size, field_ids_off = struct.unpack_from('<II', dex, 0x50)
method_ids_size, method_ids_off = struct.unpack_from('<II', dex, 0x58)

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
    off = struct.unpack_from('<I', dex, string_ids_off + idx * 4)[0]
    pos = off
    _, pos = read_uleb128(pos)
    end = dex.find(b'\x00', pos)
    return dex[pos:end].decode('utf-8', errors='replace')

def get_type(idx):
    desc_idx = struct.unpack_from('<I', dex, type_ids_off + idx * 4)[0]
    return get_string(desc_idx)

def get_method(idx):
    class_idx, proto_idx, name_idx = struct.unpack_from('<HHI', dex, method_ids_off + idx * 8)
    return get_type(class_idx) + '->' + get_string(name_idx)

# Method getFlag code_off = 0x123f34
code_off = 0x123f34
registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack_from('<HHHHII', dex, code_off)
insns = dex[code_off+16 : code_off+16+insns_size*2]

print(f"registers_size={registers_size}, ins_size={ins_size}, outs_size={outs_size}, insns_size={insns_size}")
# Note: registers are v0 to v(registers_size-1).
# Parameter registers are the last ins_size registers: v(registers_size - ins_size) .. v(registers_size - 1)
# For static getFlag(input, ctx?): let's check method prototype!

# Find method idx for getFlag
for mid in range(method_ids_size):
    class_idx, proto_idx, name_idx = struct.unpack_from('<HHI', dex, method_ids_off + mid * 8)
    if get_string(name_idx) == 'getFlag' and 'FlagstaffHill' in get_type(class_idx):
        print(f"getFlag method {mid}: class={get_type(class_idx)}, proto={proto_idx}")
        # proto
        shorty_idx, return_type_idx, parameters_off = struct.unpack_from('<III', dex, proto_ids_off + proto_idx * 12)
        print(f"  return={get_type(return_type_idx)}, shorty={get_string(shorty_idx)}")
        if parameters_off != 0:
            param_size = struct.unpack_from('<I', dex, parameters_off)[0]
            for p in range(param_size):
                ptype_idx = struct.unpack_from('<H', dex, parameters_off + 4 + p * 2)[0]
                print(f"  param {p}: {get_type(ptype_idx)}")

pc = 0
while pc < len(insns):
    op = insns[pc]
    addr = pc // 2
    
    if op == 0x22: # new-instance vAA, type@BBBB (2 words)
        vA = insns[pc+1]
        type_idx = struct.unpack_from('<H', insns, pc+2)[0]
        print(f"{addr:04x}: new-instance v{vA}, {get_type(type_idx)}")
        pc += 4
    elif op == 0x1a: # const-string vAA, string@BBBB (2 words)
        vA = insns[pc+1]
        str_idx = struct.unpack_from('<H', insns, pc+2)[0]
        print(f"{addr:04x}: const-string v{vA}, \"{get_string(str_idx)}\"")
        pc += 4
    elif op == 0x12: # const/4 vA, #+B (1 word)
        vA = insns[pc+1] & 0x0f
        val = (insns[pc+1] >> 4)
        if val >= 8: val -= 16
        print(f"{addr:04x}: const/4 v{vA}, {val}")
        pc += 2
    elif op == 0x07: # move-object vA, vB (1 word)
        vA = insns[pc+1] & 0x0f
        vB = (insns[pc+1] >> 4)
        print(f"{addr:04x}: move-object v{vA}, v{vB}")
        pc += 2
    elif op == 0x0a: # move-result vAA (1 word)
        vA = insns[pc+1]
        print(f"{addr:04x}: move-result v{vA}")
        pc += 2
    elif op == 0x0c: # move-result-object vAA (1 word)
        vA = insns[pc+1]
        print(f"{addr:04x}: move-result-object v{vA}")
        pc += 2
    elif op == 0x11: # return-object vAA (1 word)
        vA = insns[pc+1]
        print(f"{addr:04x}: return-object v{vA}")
        pc += 2
    elif op in (0x6e, 0x70): # invoke-virtual, invoke-direct {vC, vD, ...}, meth@BBBB (3 words)
        # format 35c
        kind = "invoke-virtual" if op == 0x6e else "invoke-direct"
        count = insns[pc+1] >> 4
        meth_idx = struct.unpack_from('<H', insns, pc+2)[0]
        regs = []
        c = insns[pc+4] & 0x0f
        d = (insns[pc+4] >> 4)
        e = insns[pc+5] & 0x0f
        f = (insns[pc+5] >> 4)
        a = insns[pc+1] & 0x0f
        raw_regs = [c, d, e, f, a]
        regs = [f"v{raw_regs[i]}" for i in range(count)]
        print(f"{addr:04x}: {kind} {{{', '.join(regs)}}}, {get_method(meth_idx)}")
        pc += 6
    elif op == 0xd8: # add-int/lit8 vAA, vBB, #+CC (2 words)
        vA = insns[pc+1]
        vB = insns[pc+2]
        lit = insns[pc+3]
        if lit >= 128: lit -= 256
        print(f"{addr:04x}: add-int/lit8 v{vA}, v{vB}, {lit}")
        pc += 4
    elif op == 0x8e: # int-to-char vA, vB (1 word)
        vA = insns[pc+1] & 0x0f
        vB = (insns[pc+1] >> 4)
        print(f"{addr:04x}: int-to-char v{vA}, v{vB}")
        pc += 2
    elif op == 0xb0: # add-int/2addr vA, vB (1 word)
        vA = insns[pc+1] & 0x0f
        vB = (insns[pc+1] >> 4)
        print(f"{addr:04x}: add-int/2addr v{vA}, v{vB}")
        pc += 2
    elif op == 0x38: # if-eqz vAA, +BBBB (2 words)
        vA = insns[pc+1]
        offset = struct.unpack_from('<h', insns, pc+2)[0]
        target = addr + offset
        print(f"{addr:04x}: if-eqz v{vA}, {target:04x}")
        pc += 4
    else:
        print(f"{addr:04x}: UNKNOWN OP {op:02x}")
        pc += 2
