#!/usr/bin/env python3
"""
Solve script for Riddle Registry (#530)
Category: Forensics
"""
import base64
import re
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text(encoding="utf-8").splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return "https://challenge-files.cylabacademy.net/library/1d073b2830cd8e8e6fb24a8bab184a91b61a25bea90c1d93530e92fe8a368e61/confidential.pdf"

def extract_flag_from_data(data: bytes):
    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')

    # 1. Direct text search
    text_data = data.decode('latin-1', errors='ignore')
    matches = flag_pattern.findall(text_data)
    if matches:
        return matches[0]

    # 2. Try using pypdf if available
    try:
        import pypdf
        import io
        reader = pypdf.PdfReader(io.BytesIO(data))
        if reader.metadata:
            for val in reader.metadata.values():
                if isinstance(val, str):
                    matches = flag_pattern.findall(val)
                    if matches:
                        return matches[0]
                    # Try base64 decoding
                    try:
                        decoded = base64.b64decode(val.encode('ascii')).decode('utf-8', errors='ignore')
                        matches = flag_pattern.findall(decoded)
                        if matches:
                            return matches[0]
                    except Exception:
                        pass
    except Exception:
        pass

    # 3. Regex search for metadata entries in raw PDF bytes
    # Matches patterns like /Author (YWNh...) or /Author <...>
    metadata_entries = re.findall(rb'/[A-Za-z0-9]+\s*\(([^)]+)\)', data)
    for entry in metadata_entries:
        # Normalize octal escapes in PDF literal strings (e.g., \075 -> =)
        decoded_entry = bytearray()
        i = 0
        while i < len(entry):
            if entry[i:i+1] == b'\\':
                # Check for octal
                oct_match = re.match(rb'^\\([0-7]{1,3})', entry[i:])
                if oct_match:
                    decoded_entry.append(int(oct_match.group(1), 8))
                    i += len(oct_match.group(0))
                    continue
                elif i + 1 < len(entry):
                    escape_char = entry[i+1:i+2]
                    mapping = {b'n': b'\n', b'r': b'\r', b't': b'\t', b'b': b'\b', b'f': b'\f', b'(': b'(', b')': b')', b'\\': b'\\'}
                    decoded_entry.extend(mapping.get(escape_char, escape_char))
                    i += 2
                    continue
            decoded_entry.append(entry[i])
            i += 1

        entry_str = decoded_entry.decode('latin-1', errors='ignore')
        matches = flag_pattern.findall(entry_str)
        if matches:
            return matches[0]

        try:
            b64_decoded = base64.b64decode(decoded_entry).decode('utf-8', errors='ignore')
            matches = flag_pattern.findall(b64_decoded)
            if matches:
                return matches[0]
        except Exception:
            pass

    return None

def solve():
    pdf_path = Path(__file__).resolve().parent / "confidential.pdf"
    url = get_target_url()

    # If file doesn't exist or is empty, try downloading from URL
    if not pdf_path.exists() or pdf_path.stat().st_size == 0:
        print(f"[*] Downloading PDF from {url}...")
        try:
            r = requests.get(url, timeout=15)
            r.raise_for_status()
            pdf_path.write_bytes(r.content)
            print("[+] Download complete.")
        except Exception as e:
            print(f"[-] Download failed: {e}")

    if not pdf_path.exists():
        print("[-] PDF file not found!")
        return None

    data = pdf_path.read_bytes()
    flag = extract_flag_from_data(data)

    if flag:
        print(f"[+] Flag found: {flag}")
        flag_file = Path(__file__).resolve().parent / "flag.txt"
        flag_file.write_text(flag + "\n", encoding="utf-8")
        return flag
    else:
        print("[-] Flag not found in metadata.")
        return None

if __name__ == "__main__":
    solve()
