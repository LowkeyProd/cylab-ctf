# Writeup: Silent Stream

## Header & Metadata
- **Challenge:** Silent Stream (ID: 717)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** packets.pcap, encrypt.py
- **Official Flag:** `academy{tr4ck_th3_tr4ff1c_7d327c0d}`

---

## Mô tả bài toán (Overview / Analysis)
We recovered a suspicious packet capture file that seems to contain a transferred file. The sender was kind enough to also share the script they used to encode and send it. Can you reconstruct the original file?
Download the PCAP file: <a href='https://challenge-files.cylabacademy.net/library/68531f023131b23df35aa9690733801e1154c5511a93a8434ffdfbeffb07ab6a/packets.pcap' download>here</a>. And the sender's encoding <a href='https://challenge-files.cylabacademy.net/library/68531f023131b23df35aa9690733801e1154c5511a93a8434ffdfbeffb07ab6a/encrypt.py' download>script</a>

### Hints
- The encoding script is a clue, focus on what it's doing to each byte before it's sent.
- The flag is hidden inside the file, try reconstructing and opening it.
- Don't rely on everything you see including flag format

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Silent Stream (#717)
Category: Reverse Engineering
"""
import struct
from pathlib import Path

def extract_tcp_stream(pcap_path: Path) -> bytes:
    with open(pcap_path, 'rb') as f:
        gh = f.read(24)
        if len(gh) < 24:
            raise ValueError("Invalid PCAP file: header too short")
        magic = struct.unpack('<I', gh[:4])[0]
        if magic != 0xa1b2c3d4 and magic != 0xd4c3b2a1:
            raise ValueError(f"Unsupported PCAP magic: {hex(magic)}")
        endian = '<' if magic == 0xa1b2c3d4 else '>'

        packets = []
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', ph)
            raw = f.read(incl_len)
            eth_type = struct.unpack('>H', raw[12:14])[0]
            if eth_type == 0x0800: # IPv4
                ihl = (raw[14] & 0x0f) * 4
                ip_payload = raw[14+ihl:]
                proto = raw[23]
                if proto == 6: # TCP
                    data_offset = (ip_payload[12] >> 4) * 4
                    seq = struct.unpack('>I', ip_payload[4:8])[0]
                    tcp_payload = ip_payload[data_offset:]
                    if tcp_payload:
                        packets.append((seq, tcp_payload))

    # Sort packets by sequence number
    packets.sort(key=lambda x: x[0])
    stream = bytearray()
    for seq, payload in packets:
        stream.extend(payload)

    return bytes(stream)

def decode_payload(encoded: bytes, key: int = 42) -> bytes:
    return bytes((b - key) % 256 for b in encoded)

def solve():
    print("[*] Solving Silent Stream...", flush=True)
    pcap_path = Path(__file__).parent / "packets.pcap"
    
    print(f"[*] Extracting stream from {pcap_path}...", flush=True)
    raw_stream = extract_tcp_stream(pcap_path)
    print(f"[+] Reassembled {len(raw_stream)} bytes of payload.", flush=True)

    print("[*] Reversing byte transformation with key 42...", flush=True)
    decoded_file = decode_payload(raw_stream, key=42)

    # Validate JPEG format
    if decoded_file.startswith(b'\xff\xd8') and decoded_file.endswith(b'\xff\xd9'):
        print("[+] Successfully decoded JPEG image file!", flush=True)
        out_jpg = Path(__file__).parent / "reconstructed.jpg"
        with open(out_jpg, "wb") as f:
            f.write(decoded_file)
        print(f"[+] Reconstructed image saved to {out_jpg}", flush=True)
    else:
        print("[!] Warning: Decoded file does not match expected JPEG markers", flush=True)

    # From visual analysis of the reconstructed JPEG:
    # The image contains red text: "academy[tr4ck_th3_tr4ff1c_7d327c0d]"
    # As noted in hints ("Don't rely on everything you see including flag format"),
    # the flag format uses standard curly braces {}.
    flag = "academy{tr4ck_th3_tr4ff1c_7d327c0d}"

    flag_path = Path(__file__).parent / "flag.txt"
    with open(flag_path, "w", encoding="utf-8") as f:
        f.write(flag + "\n")
    print(f"[+] Flag written to {flag_path}: {flag}", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{tr4ck_th3_tr4ff1c_7d327c0d}
```
