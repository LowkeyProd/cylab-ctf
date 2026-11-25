import struct

with open('extracted/resources.arsc', 'rb') as f:
    arsc = f.read()

def parse_string_pool(data, off):
    # ResStringPool_header
    type, header_size, size, strings_count, styles_count, flags, strings_start, styles_start = struct.unpack_from('<HHIIIIII', data, off)
    string_offsets = struct.unpack_from(f'<{strings_count}I', data, off + header_size)
    strings = []
    pool_data = data[off + strings_start :]
    is_utf8 = bool(flags & (1 << 8))
    for s_off in string_offsets:
        if is_utf8:
            # u8 length: length might be 1 or 2 bytes
            pos = s_off
            # skip utf-16 len
            if pool_data[pos] & 0x80:
                pos += 2
            else:
                pos += 1
            # utf-8 len
            if pool_data[pos] & 0x80:
                pos += 2
            else:
                l = pool_data[pos]
                pos += 1
            s = pool_data[pos : pos + l].decode('utf-8', errors='replace')
        else:
            # utf-16
            pos = s_off
            l = struct.unpack_from('<H', pool_data, pos)[0]
            pos += 2
            if l & 0x8000:
                l = ((l & 0x7fff) << 16) | struct.unpack_from('<H', pool_data, pos)[0]
                pos += 2
            s = pool_data[pos : pos + l*2].decode('utf-16le', errors='replace')
        strings.append(s)
    return strings, off + size

# First string pool is global string pool
header_type, header_size, size = struct.unpack_from('<HHI', arsc, 0)
print(f"Header: type={header_type:#x}, header_size={header_size}, size={size}")

global_strings, next_off = parse_string_pool(arsc, header_size)
print(f"Global strings count: {len(global_strings)}")

# Search through chunks
off = next_off
while off < len(arsc):
    c_type, c_hsize, c_size = struct.unpack_from('<HHI', arsc, off)
    # RES_TABLE_PACKAGE_TYPE = 0x0200
    if c_type == 0x0200:
        pkg_id = struct.unpack_from('<I', arsc, off + 8)[0]
        pkg_name = arsc[off + 12 : off + 12 + 256].decode('utf-16le').split('\x00')[0]
        type_strings_off, last_public_type, key_strings_off, last_public_key = struct.unpack_from('<IIII', arsc, off + 268)
        print(f"Package: id={pkg_id:#x}, name={pkg_name}")
        
        type_strings, _ = parse_string_pool(arsc, off + type_strings_off)
        key_strings, _ = parse_string_pool(arsc, off + key_strings_off)
        print(f"Types: {type_strings}")
        print(f"Key strings count: {len(key_strings)}")
        
        # Walk subchunks within package
        sub_off = off + c_hsize
        while sub_off < off + c_size:
            s_type, s_hsize, s_size = struct.unpack_from('<HHI', arsc, sub_off)
            # RES_TABLE_TYPE_TYPE = 0x0201
            # RES_TABLE_TYPE_SPEC_TYPE = 0x0202
            if s_type == 0x0201: # RES_TABLE_TYPE_TYPE
                tid = arsc[sub_off + 8]
                entry_count, entries_start = struct.unpack_from('<II', arsc, sub_off + 12)
                type_name = type_strings[tid - 1] if tid - 1 < len(type_strings) else f"type_{tid}"
                if type_name == 'string':
                    entry_offsets = struct.unpack_from(f'<{entry_count}I', arsc, sub_off + s_hsize)
                    for e_idx, e_off in enumerate(entry_offsets):
                        if e_off != 0xffffffff:
                            # entry
                            res_id = (pkg_id << 24) | (tid << 16) | e_idx
                            entry_data_off = sub_off + entries_start + e_off
                            flags, key_idx = struct.unpack_from('<HH', arsc, entry_data_off)
                            key_name = key_strings[key_idx] if key_idx < len(key_strings) else "unknown"
                            # Res_value
                            # size(2), res0(1), dataType(1), data(4)
                            v_size, v_res0, v_dataType, v_data = struct.unpack_from('<HBBI', arsc, entry_data_off + 8)
                            val_str = ""
                            if v_dataType == 0x03: # TYPE_STRING
                                val_str = global_strings[v_data]
                            else:
                                val_str = f"type:{v_dataType} data:{v_data:#x}"
                            if res_id in (0x7f0b002f, 0x7f0b002c) or key_name in ('password', 'hint'):
                                print(f"  Entry {e_idx:#06x} ({res_id:#010x}): key='{key_name}', value='{val_str}'")
            sub_off += s_size
        off += c_size
    else:
        off += c_size
