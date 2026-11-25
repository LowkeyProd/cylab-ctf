#!/usr/bin/env python3
"""
Solve script for ReadMyCert (#367)
Category: Cryptography
"""
from pathlib import Path
import re
from cryptography import x509
from cryptography.x509.oid import NameOID

def solve():
    print("[*] Solving ReadMyCert...")
    csr_path = Path(__file__).parent / "readmycert.csr"

    flag = None
    if csr_path.exists():
        csr_data = csr_path.read_bytes()
        try:
            csr = x509.load_pem_x509_csr(csr_data)
            cn_attributes = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cn_attributes:
                candidate = cn_attributes[0].value
                if "academy{" in candidate or "picoCTF{" in candidate:
                    flag = candidate
        except Exception as e:
            print(f"[-] Error parsing CSR with cryptography: {e}")

        if not flag:
            # Fallback regex search on raw / decoded CSR data
            match = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', csr_data.decode(errors='ignore'))
            if match:
                flag = match.group(1)

    if not flag:
        raise ValueError("Flag could not be extracted from readmycert.csr")

    print(f"[+] Flag found: {flag}")
    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag.strip() + "\n", encoding="utf-8")
    print(f"[+] Flag written to {flag_path}")
    return flag

if __name__ == "__main__":
    solve()
