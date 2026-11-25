import struct
import base64

with open('myNetworkTraffic.pcap', 'rb') as f:
    data = f.read()

offset = 24
pkts = []
pkt_idx = 0
while offset < len(data):
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', data[offset:offset+16])
    offset += 16
    pkt = data[offset:offset+incl_len]
    offset += incl_len
    pkt_idx += 1
    ihl = (pkt[0] & 0x0f) * 4
    tcp_offset = ihl
    data_offset = ((pkt[tcp_offset + 12] >> 4) & 0x0f) * 4
    payload = pkt[tcp_offset + data_offset:]
    pkts.append({
        'idx': pkt_idx,
        'ts_sec': ts_sec,
        'ts_usec': ts_usec,
        'payload': payload
    })

# Filter packets that have valid base64 decodable to printable ASCII
print("=== Filtered packets ===")
valid = []
for p in pkts:
    try:
        dec = base64.b64decode(p['payload']).decode('ascii')
        valid.append((p['ts_usec'], p['idx'], p['payload'], dec))
    except Exception:
        pass

valid.sort()
full_flag = ""
for usec, idx, b64_raw, dec in valid:
    print(f"usec: {usec} | idx: {idx:02d} | b64: {b64_raw.decode()} | dec: {dec}")
    if dec.startswith("academy{") or full_flag:
        full_flag += dec
    elif dec == "academy":
        full_flag += dec

print("\nConcatenated:")
print(full_flag)

# Wait, what if academy and {1t_w4s... are separate?
parts = [v[3] for v in valid]
print("All decoded parts joined:", "".join(parts))
