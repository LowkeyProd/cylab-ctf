# Writeup: Wireshark twoo twooo two twoo...

## Header & Metadata
- **Challenge:** Wireshark twoo twooo two twoo... (ID: 110)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** shark2.pcapng
- **Official Flag:** `academy{dns_3xf1l_ftw_deadbeef}`

---

## Mô tả bài toán (Overview / Analysis)
Can you find the flag?
<a href='https://challenge-files.cylabacademy.net/library/5875fed4c5d104178ca32dd2d5855add80fe6defd73da810e3f7d70efb59fdfb/shark2.pcapng' download>shark2.pcapng</a>

### Hints
- Did you really find _the_ flag?
- Look for traffic that seems suspicious.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity analyzing & repairing solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Wireshark twoo twooo two twoo... (#110)
Category: Forensics
"""
import base64
import os
import re
import sys
from pathlib import Path

def solve():
    print("[*] Solving Wireshark twoo twooo two twoo......")
    pcap_path = Path(__file__).parent / "shark2.pcapng"
    if not pcap_path.exists():
        pcap_path = Path("shark2.pcapng")

    from scapy.all import rdpcap, DNS, IP

    packets = rdpcap(str(pcap_path))

    # Identify DNS queries to suspicious external IP (18.217.1.57)
    # The hint warns: "Did you really find _the_ flag?" and "traffic that seems suspicious".
    # Normal DNS queries were sent to 8.8.8.8 as decoys, whereas the exfiltration was directed to 18.217.1.57.
    subdomains = []
    seen = set()
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(IP) and pkt[DNS].qr == 0:
            if pkt[IP].dst == "18.217.1.57":
                qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore")
                sub = qname.split(".")[0]
                if sub not in seen:
                    seen.add(sub)
                    subdomains.append(sub)

    encoded_str = "".join(subdomains)
    flag = base64.b64decode(encoded_str).decode("utf-8", errors="ignore").strip()

    print(f"[*] Found flag: {flag}")

    flag_file = Path(__file__).parent / "flag.txt"
    with open(flag_file, "w", encoding="utf-8") as f:
        f.write(flag + "\n")

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{dns_3xf1l_ftw_deadbeef}
```
