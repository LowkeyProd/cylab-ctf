#!/usr/bin/env python3
"""
Solve script for shark on wire 1 (#30)
Extracts UDP stream payloads from shark-on-wire-1-capture.pcap to recover the flag.
"""
import os
import re
import struct

PCAP_FILE = os.path.join(os.path.dirname(__file__), "shark-on-wire-1-capture.pcap")
FLAG_FILE = os.path.join(os.path.dirname(__file__), "flag.txt")

def extract_udp_streams(pcap_path):
    with open(pcap_path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            return {}
        magic, = struct.unpack("<I", header[:4])
        endian = "<" if magic in (0xa1b2c3d4, 0xa1b23c4d) else ">"

        streams = {}
        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
            pkt_data = f.read(incl_len)
            if len(pkt_data) < 14:
                continue

            eth_type = struct.unpack(">H", pkt_data[12:14])[0]
            if eth_type != 0x0800:
                continue

            ip_hdr = pkt_data[14:]
            ihl = (ip_hdr[0] & 0x0f) * 4
            protocol = ip_hdr[9]
            if protocol != 17:  # UDP
                continue

            src_ip = ".".join(map(str, ip_hdr[12:16]))
            dst_ip = ".".join(map(str, ip_hdr[16:20]))
            udp_hdr = ip_hdr[ihl:]
            src_port, dst_port, udp_len = struct.unpack(">HHH", udp_hdr[:6])
            payload = udp_hdr[8:udp_len]

            key = (src_ip, src_port, dst_ip, dst_port)
            streams.setdefault(key, []).append(payload)

    return streams

def solve():
    streams = extract_udp_streams(PCAP_FILE)
    flag_candidates = []

    for key, payloads in streams.items():
        data = b"".join(payloads).decode(errors="ignore")
        matches = re.findall(r"(?:academy|picoCTF)\{[^}]+\}", data)
        for match in matches:
            if "N0t_a_fLag" not in match:
                flag_candidates.append(match)

    if not flag_candidates:
        raise ValueError("Flag not found in packet capture!")

    flag = flag_candidates[0]
    with open(FLAG_FILE, "w") as f:
        f.write(flag + "\n")

    print(flag)
    return flag

if __name__ == "__main__":
    solve()
