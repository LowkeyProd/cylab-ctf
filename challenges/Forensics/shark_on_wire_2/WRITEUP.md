# Writeup: shark on wire 2

## Header & Metadata
- **Challenge:** shark on wire 2 (ID: 84)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `https://challenge-files.cylabacademy.net/library/f76620763560ca0683be36e0ed4648743f969ab4d852fda0d8fb4d3ae21a173d/shark-on-wire-2-capture.pcap`
- **Attached Files:** shark-on-wire-2-capture.pcap
- **Official Flag:** `academy{p1LLf3r3d_data_v1a_st3g0}`

---

## Mô tả bài toán (Overview / Analysis)

We found this <a href='https://challenge-files.cylabacademy.net/library/f76620763560ca0683be36e0ed4648743f969ab4d852fda0d8fb4d3ae21a173d/shark-on-wire-2-capture.pcap' download>packet capture</a>. Recover the flag that was pilfered from the network.

### Hints
None

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for shark on wire 2 (#84)
Category: Forensics
Recovers the exfiltrated flag from shark-on-wire-2-capture.pcap
"""
import os
import struct

PCAP_FILE = os.path.join(os.path.dirname(__file__), "shark-on-wire-2-capture.pcap")
FLAG_FILE = os.path.join(os.path.dirname(__file__), "flag.txt")

def extract_flag(pcap_path):
    with open(pcap_path, "rb") as f:
        # PCAP Global Header: 24 bytes
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError("File too small to be a valid PCAP")
        magic = gh[:4]
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"

        flag_chars = []
        started = False

        while True:
            # Packet Header: 16 bytes
            ph = f.read(16)
            if len(ph) < 16:
                break
            sec, usec, incl_len, orig_len = struct.unpack(endian + "IIII", ph)
            pkt = f.read(incl_len)

            # Ethernet header (14 bytes): check IPv4 ethertype 0x0800
            if len(pkt) < 14:
                continue
            eth_proto = struct.unpack("!H", pkt[12:14])[0]
            if eth_proto != 0x0800:
                continue

            # IPv4 header
            ip_hdr = pkt[14:]
            if len(ip_hdr) < 20:
                continue
            ihl = (ip_hdr[0] & 0x0F) * 4
            proto = ip_hdr[9]
            if proto != 17:  # 17 = UDP
                continue

            # UDP header (8 bytes)
            udp_hdr = ip_hdr[ihl : ihl + 8]
            if len(udp_hdr) < 8:
                continue
            sport, dport, ulen, cksum = struct.unpack("!HHHH", udp_hdr)
            payload = ip_hdr[ihl + 8 : ihl + ulen]

            # In shark on wire 2, the flag transmission is sent over UDP port 22
            # Delimited by payload "start" and "end"
            # Characters are encoded in the source port as: ord(char) + 5000
            if dport == 22:
                if payload == b"start":
                    started = True
                elif payload == b"end":
                    break
                elif started:
                    flag_chars.append(chr(sport - 5000))

        return "".join(flag_chars)

def main():
    flag = extract_flag(PCAP_FILE)
    print(flag)
    with open(FLAG_FILE, "w") as f:
        f.write(flag + "\n")

if __name__ == "__main__":
    main()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{p1LLf3r3d_data_v1a_st3g0}
```
