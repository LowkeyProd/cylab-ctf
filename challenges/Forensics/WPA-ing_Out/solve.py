#!/usr/bin/env python3
"""
Solve script for WPA-ing Out (#237)
Category: Forensics

Verified cryptographically by recalculating IEEE 802.11 4-way handshake MIC.
"""
import hashlib
import hmac
from pathlib import Path
from scapy.all import rdpcap, EAPOL, Dot11

def custom_prf512(key, prefix, data):
    r = b""
    for i in range(4):
        hm = hmac.new(key, prefix + b"\x00" + data + bytes([i]), hashlib.sha1)
        r += hm.digest()
    return r[:64]

def verify_handshake(pcap_path: str, ssid: str, passphrase: str) -> bool:
    pkts = rdpcap(pcap_path)
    p49 = pkts[49]  # AP -> Client (ANonce)
    p51 = pkts[51]  # Client -> AP (SNonce + MIC)

    raw49 = bytes(p49[EAPOL])
    raw51 = bytes(p51[EAPOL])

    anonice = raw49[17:49]
    snonce = raw51[17:49]
    mic_in_pkt = raw51[81:97]

    ap_mac = bytes.fromhex(p49[Dot11].addr2.replace(":", ""))
    sta_mac = bytes.fromhex(p49[Dot11].addr1.replace(":", ""))

    b_data = min(ap_mac, sta_mac) + max(ap_mac, sta_mac) + min(anonice, snonce) + max(anonice, snonce)

    pmk = hashlib.pbkdf2_hmac("sha1", passphrase.encode(), ssid.encode(), 4096, 32)
    ptk = custom_prf512(pmk, b"Pairwise key expansion", b_data)
    kck = ptk[:16]

    eapol_zero_mic = raw51[:81] + b"\x00" * 16 + raw51[97:]
    mic_computed = hmac.new(kck, eapol_zero_mic, hashlib.md5).digest()

    return mic_computed == mic_in_pkt

def solve():
    print("[*] Solving WPA-ing Out...")
    pcap_path = Path(__file__).parent / "wpa-ing_out.pcap"
    ssid = "Gone_Surfing"
    passphrase = "mickeymouse"

    if verify_handshake(str(pcap_path), ssid, passphrase):
        print(f"[+] Cryptographic verification SUCCESS for '{passphrase}'")
        flag = f"academy{{{passphrase}}}"
        print(f"[+] Flag: {flag}")
        with open(Path(__file__).parent / "flag.txt", "w") as f:
            f.write(flag + "\n")
        return flag
    else:
        raise ValueError("Verification failed!")

if __name__ == "__main__":
    solve()
