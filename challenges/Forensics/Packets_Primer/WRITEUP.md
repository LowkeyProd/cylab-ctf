# Writeup: Packets Primer

## Header & Metadata
- **Challenge:** Packets Primer (ID: 286)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** network-dump.flag.pcap
- **Official Flag:** `academy{p4ck37_5h4rk_5b0c3582}`

---

## Mô tả bài toán (Overview / Analysis)
Download the packet capture file and use packet analysis software to find the
flag.
- <a href='https://challenge-files.cylabacademy.net/library/72f70ef7e37699557d64de3449e8511f7338328d38bbe18919206c75d1d4f863/network-dump.flag.pcap' download>Download packet capture</a>

### Hints
- Wireshark, if you can install and use it, is probably the most beginner
  friendly packet analysis software product.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity analyzing & repairing solve.py.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Packets Primer (#286)
Category: Forensics
"""
import re
from pathlib import Path

def solve():
    print("[*] Solving Packets Primer...")
    pcap_path = Path(__file__).parent / "network-dump.flag.pcap"
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # First attempt: Try using scapy if available
    flag = None
    try:
        from scapy.all import rdpcap, Raw
        packets = rdpcap(str(pcap_path))
        for pkt in packets:
            if Raw in pkt:
                payload = pkt[Raw].load.decode(errors="ignore")
                # Remove spaces
                cleaned = "".join(payload.split())
                match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", cleaned)
                if match:
                    flag = match.group(1)
                    break
    except Exception as e:
        print(f"[!] Scapy parsing failed or not available ({e}), falling back to raw binary search...")

    # Fallback: Raw binary extraction
    if not flag:
        data = pcap_path.read_bytes()
        match = re.search(rb"([a-zA-Z0-9_\{\}\s]+)", data)
        # Search specifically for formatted flag with spaces
        regex = re.compile(rb"((?:a\s*c\s*a\s*d\s*e\s*m\s*y|p\s*i\s*c\s*o\s*C\s*T\s*F)\s*\{[^}]+\})")
        m = regex.search(data)
        if m:
            flag = "".join(m.group(1).decode(errors="ignore").split())

    if flag:
        print(f"[+] Flag found: {flag}")
        flag_file = Path(__file__).parent / "flag.txt"
        flag_file.write_text(flag.strip())
        print(f"[+] Saved flag to {flag_file}")
        return flag
    else:
        raise ValueError("Flag not found in packet capture.")

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{p4ck37_5h4rk_5b0c3582}
```
