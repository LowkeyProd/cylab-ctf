#!/usr/bin/env python3
"""
Solve script for Milkslap (#139)
Category: Forensics

Methodology:
- Dynamically parse connection.cfg to retrieve the target server endpoint.
- Discover and fetch the animated sprite image asset (concat_v.png) referenced in style.css.
- Analyze bitplane steganography: LSB on the Blue channel (b1,b,msb,xy).
- Extract and verify the flag token and write it to flag.txt.
"""
import re
import urllib.parse
from pathlib import Path
import numpy as np
import requests
from PIL import Image

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host = None
    port = None
    url = None
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("URL="):
                url = line.split("=", 1)[1].strip()
            elif line.startswith("HOST="):
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT="):
                port = line.split("=", 1)[1].strip()
    if url:
        return url.rstrip('/')
    if host and port:
        return f"http://{host}:{port}"
    return "http://chatelaine.cylabacademy.net:18227"

def solve():
    base_url = get_target_url()
    print(f"[*] Target URL: {base_url}", flush=True)

    img_filename = "concat_v.png"
    img_path = Path(__file__).resolve().parent / img_filename

    # If image does not exist locally, fetch it from target
    if not img_path.exists() or img_path.stat().st_size == 0:
        print("[*] Fetching style.css to locate image asset...", flush=True)
        try:
            css_resp = requests.get(f"{base_url}/style.css", timeout=10)
            m = re.search(r'url\((.*?)\)', css_resp.text)
            if m:
                img_relative = m.group(1).strip('\'"')
                img_url = urllib.parse.urljoin(base_url + '/', img_relative)
            else:
                img_url = f"{base_url}/{img_filename}"
        except Exception as e:
            print(f"[-] Error querying style.css: {e}, falling back to default image URL", flush=True)
            img_url = f"{base_url}/{img_filename}"

        print(f"[*] Downloading {img_url} ...", flush=True)
        r = requests.get(img_url, stream=True, timeout=30)
        r.raise_for_status()
        with open(img_path, 'wb') as f:
            for chunk in r.iter_content(chunk_size=65536):
                f.write(chunk)
        print(f"[+] Download complete: {img_path.stat().st_size} bytes", flush=True)
    else:
        print(f"[*] Using local image {img_filename} ({img_path.stat().st_size} bytes)", flush=True)

    print("[*] Extracting LSB steganography from blue channel...", flush=True)
    img = Image.open(img_path)
    w, h = img.size

    # The flag is embedded in the initial rows of the image (b1,b,msb,xy)
    # Read the top scanlines for fast and efficient extraction
    rows_to_read = min(h, 200)
    cropped = img.crop((0, 0, w, rows_to_read))
    arr = np.array(cropped)

    # Blue channel (index 2) least significant bit
    b_channel_lsb = arr[:, :, 2] & 1
    bits = b_channel_lsb.flatten()

    # Pack bits into bytes (MSB order as identified by zsteg / bitplane analysis)
    decoded_bytes = np.packbits(bits, bitorder='big').tobytes()

    # Search for flag pattern
    flag_pattern = re.compile(rb'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    matches = flag_pattern.findall(decoded_bytes)

    decoy_words = [b'fake', b'decoy', b'honey', b'not_the_flag', b'dummy']
    for match in matches:
        if any(decoy in match.lower() for decoy in decoy_words):
            continue
        flag = match.decode('utf-8', errors='ignore')
        print(f"[+] Flag found: {flag}", flush=True)

        flag_file = Path(__file__).resolve().parent / "flag.txt"
        flag_file.write_text(flag.strip() + "\n", encoding='utf-8')
        print(f"[+] Saved flag to {flag_file}", flush=True)
        return flag

    print("[-] Flag not found in extracted data.", flush=True)
    return None

if __name__ == "__main__":
    solve()
