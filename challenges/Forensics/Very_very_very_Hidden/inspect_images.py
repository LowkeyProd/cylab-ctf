import struct

def parse_png(filename):
    print(f"=== {filename} ===")
    with open(filename, "rb") as f:
        sig = f.read(8)
        assert sig == b"\x89PNG\r\n\x1a\n"
        while True:
            chunk_hdr = f.read(8)
            if not chunk_hdr:
                break
            length, ctype = struct.unpack(">I4s", chunk_hdr)
            data = f.read(length)
            crc = f.read(4)
            print(f"Chunk {ctype.decode('latin1')}: length={length}")
            if ctype != b"IDAT":
                print("  data:", repr(data[:100]))

parse_png("duck.png")
parse_png("evil_duck.png")
