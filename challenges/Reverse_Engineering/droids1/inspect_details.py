import struct

with open('extracted/classes.dex', 'rb') as f:
    dex = f.read()

string_ids_size, string_ids_off = struct.unpack_from('<II', dex, 0x38)
type_ids_size, type_ids_off = struct.unpack_from('<II', dex, 0x40)
field_ids_size, field_ids_off = struct.unpack_from('<II', dex, 0x50)
method_ids_size, method_ids_off = struct.unpack_from('<II', dex, 0x58)
class_defs_size, class_defs_off = struct.unpack_from('<II', dex, 0x60)

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

def read_uleb128(data, off):
    res = 0
    shift = 0
    while True:
        b = data[off]
        off += 1
        res |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, off

# Find R$string
for i in range(class_defs_size):
    class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off = struct.unpack_from('<IIIIIIII', dex, class_defs_off + i * 32)
    cname = types[class_idx]
    if 'R$string' in cname:
        print("Found", cname)
        # static values
        # Let's read static fields in class_data
        off = class_data_off
        static_fields_size, off = read_uleb128(dex, off)
        instance_fields_size, off = read_uleb128(dex, off)
        direct_methods_size, off = read_uleb128(dex, off)
        virtual_methods_size, off = read_uleb128(dex, off)
        
        f_idx = 0
        field_list = []
        for _ in range(static_fields_size):
            f_diff, off = read_uleb128(dex, off)
            f_idx += f_diff
            access, off = read_uleb128(dex, off)
            # field_id: class_idx (ushort), type_idx (ushort), name_idx (uint)
            fc_idx, ft_idx, fn_idx = struct.unpack_from('<HHI', dex, field_ids_off + f_idx * 8)
            field_list.append((strings[fn_idx], f_idx))
            
        # read static values
        if static_values_off != 0:
            sv_off = static_values_off
            size, sv_off = read_uleb128(dex, sv_off)
            for j in range(size):
                # encoded value
                header = dex[sv_off]
                sv_off += 1
                vtype = header & 0x1f
                varg = header >> 5
                val_bytes = dex[sv_off : sv_off + varg + 1]
                sv_off += varg + 1
                # if int (0x04)
                val = int.from_bytes(val_bytes, 'little', signed=True)
                if j < len(field_list):
                    name = field_list[j][0]
                    if val in (0x7f0b002f, 0x7f0b002c) or 'pass' in name.lower() or 'flag' in name.lower():
                        print(f"  Field {name} = {val:#x} ({val})")
