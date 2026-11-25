# Writeup: Eavesdrop

## Header & Metadata
- **Challenge:** Eavesdrop (ID: 264)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Forensics
- **Server / Instance:** `N/A`
- **Attached Files:** capture.flag.pcap
- **Official Flag:** `academy{nc_73115_411_70df147f}`

---

## Mô tả bài toán (Overview / Analysis)
Download this packet capture and find the flag.
- <a href='https://challenge-files.cylabacademy.net/library/5fbc072db568fc9f9b35f20d39dc6b54226da29aa4d4277a6906489ad3fee9f5/capture.flag.pcap' download>Download packet capture</a>

### Hints
- All we know is that this packet capture includes a chat conversation and a
  file transfer.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Eavesdrop (#264)
Category: Forensics

Extracts the encrypted file and decryption parameters from capture.flag.pcap,
then decrypts the flag using DES3-CBC with EVP_BytesToKey (SHA256).
"""
import re
import hashlib
from pathlib import Path
from Crypto.Cipher import DES3
from scapy.all import rdpcap, TCP, Raw

def load_config():
    """Load configuration from connection.cfg dynamically if present."""
    cfg_path = Path(__file__).parent / "connection.cfg"
    config = {}
    if cfg_path.exists():
        for line in cfg_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def evp_bytes_to_key(password: bytes, salt: bytes, key_len: int = 24, iv_len: int = 8, hash_name: str = "sha256"):
    """Derive key and IV using OpenSSL's EVP_BytesToKey algorithm."""
    hasher_fn = getattr(hashlib, hash_name)
    key_iv = b""
    d_i = b""
    while len(key_iv) < (key_len + iv_len):
        d_i = hasher_fn(d_i + password + salt).digest()
        key_iv += d_i
    key = key_iv[:key_len]
    iv = key_iv[key_len:key_len + iv_len]
    return key, iv

def solve():
    print("[*] Solving Eavesdrop...", flush=True)
    load_config()

    pcap_path = Path(__file__).parent / "capture.flag.pcap"
    if not pcap_path.exists():
        raise FileNotFoundError(f"Missing {pcap_path}")

    print(f"[*] Reading pcap from {pcap_path}...", flush=True)
    packets = rdpcap(str(pcap_path))

    command_text = ""
    file_data = b""

    # Analyze TCP streams
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if b"openssl" in payload:
                try:
                    command_text = payload.decode("utf-8", errors="ignore")
                    print(f"[*] Found command in traffic: {command_text.strip()}", flush=True)
                except Exception:
                    pass
            if payload.startswith(b"Salted__"):
                file_data = payload
                print(f"[*] Found salted encrypted payload ({len(file_data)} bytes)", flush=True)

    # Extract password from command
    password = b"supersecretpassword123"
    if command_text:
        match = re.search(r"-k\s+(\S+)", command_text)
        if match:
            password = match.group(1).encode("utf-8")
            print(f"[*] Extracted password: {password.decode()}", flush=True)

    if not file_data:
        raise ValueError("Could not find encrypted file payload in packet capture.")

    salt = file_data[8:16]
    ciphertext = file_data[16:]

    # Decrypt using SHA-256 (OpenSSL 1.1+ default) or MD5 fallback
    flag = ""
    for hash_name in ["sha256", "md5"]:
        try:
            key, iv = evp_bytes_to_key(password, salt, key_len=24, iv_len=8, hash_name=hash_name)
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            decrypted = cipher.decrypt(ciphertext)
            pad_len = decrypted[-1]
            if 1 <= pad_len <= 8:
                candidate = decrypted[:-pad_len].decode("utf-8", errors="ignore")
                if "academy{" in candidate or "picoCTF{" in candidate:
                    flag = candidate.strip()
                    break
        except Exception:
            continue

    if not flag:
        raise ValueError("Failed to decrypt flag.")

    # Validate not decoy
    for decoy in ["decoy", "fake", "honeypot", "dummy"]:
        if decoy in flag.lower():
            raise ValueError(f"Flag rejected as decoy: {flag}")

    print(f"[+] Flag found: {flag}", flush=True)

    # Write flag to flag.txt
    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag)
    print(f"[+] Flag saved to {flag_path}", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{nc_73115_411_70df147f}
```
