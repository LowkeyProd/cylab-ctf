# Writeup: Ph4nt0m 1ntrud3r

## Header & Metadata
- **Challenge:** Ph4nt0m 1ntrud3r (ID: 459)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** myNetworkTraffic.pcap
- **Official Flag:** `academy{1t_w4snt_th4t_34sy_tbh_4r_6b09861f}`

---

## Mô tả bài toán (Overview / Analysis)
A digital ghost has breached my defenses, and my sensitive data has been stolen! 😱💻 Your mission is to uncover how this phantom intruder infiltrated my system and retrieve the hidden flag.

To solve this challenge, you'll need to analyze the provided PCAP file and track down the attack method. The attacker has cleverly concealed his moves in well timely manner. Dive into the network traffic, apply the right filters and show off your forensic prowess and unmask the digital intruder!

Find the PCAP file here <a href='https://challenge-files.cylabacademy.net/library/828ca80eed550dbc9645ad6c2aa5c2061b2dd2e8e4098b1c7fe6d639459ea5a5/myNetworkTraffic.pcap' download>Network Traffic PCAP file</a> and try to get the flag.


### Hints
- Filter your packets to narrow down your search.
- Attacks were done in timely manner.
- Time is essential

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via writeup solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Ph4nt0m 1ntrud3r (#459)
Category: Forensics | Difficulty: Easy
"""
import os
import struct
import base64
import re
from pathlib import Path
import urllib.request

def get_target_config():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def parse_pcap(pcap_path):
    with open(pcap_path, 'rb') as f:
        data = f.read()

    magic = data[:4]
    endian = '<' if magic in [b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'] else '>'
    
    offset = 24
    packets = []
    pkt_idx = 0
    while offset < len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', data[offset:offset+16])
        offset += 16
        pkt = data[offset:offset+incl_len]
        offset += incl_len
        pkt_idx += 1
        
        ihl = (pkt[0] & 0x0f) * 4
        tcp_offset = ihl
        data_offset = ((pkt[tcp_offset + 12] >> 4) & 0x0f) * 4
        payload = pkt[tcp_offset + data_offset:]
        ts = ts_sec + ts_usec / 1e6
        packets.append({
            'idx': pkt_idx,
            'ts': ts,
            'payload': payload
        })
    return packets

def solve():
    script_dir = Path(__file__).resolve().parent
    config = get_target_config()
    pcap_file = script_dir / "myNetworkTraffic.pcap"

    if not pcap_file.exists() and "URL" in config:
        print(f"[*] Downloading PCAP from {config['URL']}...", flush=True)
        urllib.request.urlretrieve(config["URL"], pcap_file)

    packets = parse_pcap(pcap_file)
    print(f"[*] Parsed {len(packets)} packets from {pcap_file.name}", flush=True)

    # Sort packets by timestamp (Time is essential)
    sorted_packets = sorted(packets, key=lambda p: p['ts'])

    # Decode valid base64 payloads
    decoded_chunks = []
    for p in sorted_packets:
        try:
            chunk = base64.b64decode(p['payload']).decode('ascii')
            # Check if chunk contains printable characters
            if all(32 <= ord(c) < 127 for c in chunk):
                decoded_chunks.append(chunk)
        except Exception:
            continue

    combined = "".join(decoded_chunks)
    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    match = flag_pattern.search(combined)

    if match:
        flag = match.group(0)
        print(f"[+] Flag found: {flag}", flush=True)
        flag_file = script_dir / "flag.txt"
        flag_file.write_text(flag.strip() + "\n")
        return flag
    else:
        print(f"[-] Could not match flag pattern. Combined string: {combined}", flush=True)
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{1t_w4snt_th4t_34sy_tbh_4r_6b09861f}
```
