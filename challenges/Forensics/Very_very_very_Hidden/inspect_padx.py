import struct

with open("evil_duck.png", "rb") as f:
    f.seek(8)
    while True:
        chunk_hdr = f.read(8)
        if not chunk_hdr:
            break
        length, ctype = struct.unpack(">I4s", chunk_hdr)
        data = f.read(length)
        crc = f.read(4)
        if ctype == b"paDx":
            print(f"paDx length: {length}")
            # check non-zero bytes
            non_zeros = [(i, b) for i, b in enumerate(data) if b != 0]
            print(f"Non-zero byte count: {len(non_zeros)}")
            if non_zeros:
                print(f"First non-zero: at {non_zeros[0][0]}: {data[non_zeros[0][0]:non_zeros[0][0]+100]}")
            # print unique bytes
            print("Unique bytes:", set(data))
            with open("padx_data.bin", "wb") as out:
                out.write(data)
