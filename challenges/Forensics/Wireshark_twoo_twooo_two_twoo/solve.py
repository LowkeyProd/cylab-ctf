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
