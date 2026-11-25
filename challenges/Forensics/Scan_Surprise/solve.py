#!/usr/bin/env python3
"""
Solve script for Scan Surprise (#444)
Category: Forensics
"""
import io
import re
import zipfile
from pathlib import Path
import requests
import cv2
import numpy as np

def get_config():
    cfg = {}
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg

def solve():
    cfg = get_config()
    target_url = cfg.get("URL", "https://challenge-files.cylabacademy.net/library/e48eb57d2e3cbfa7fc0b3f0023b5de68ffbea6ed090caca4ceeaf403fdc00f9b/challenge.zip")
    local_zip = Path(__file__).resolve().parent / "challenge.zip"

    zip_bytes = None
    if target_url:
        print(f"[*] Downloading challenge zip from: {target_url}")
        try:
            resp = requests.get(target_url, timeout=15)
            if resp.status_code == 200:
                zip_bytes = resp.content
                print(f"[+] Downloaded {len(zip_bytes)} bytes")
        except Exception as e:
            print(f"[-] Download error: {e}")

    if not zip_bytes and local_zip.exists():
        print(f"[*] Loading from local file: {local_zip}")
        zip_bytes = local_zip.read_bytes()

    if not zip_bytes:
        raise RuntimeError("Failed to obtain challenge.zip from URL or local file")

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        png_candidates = [name for name in zf.namelist() if name.endswith(".png")]
        if not png_candidates:
            raise RuntimeError("No PNG files found in challenge archive")
        png_name = png_candidates[0]
        print(f"[*] Extracting {png_name}")
        png_data = zf.read(png_name)

    # Decode image using OpenCV
    img_np = np.frombuffer(png_data, np.uint8)
    img = cv2.imdecode(img_np, cv2.IMREAD_COLOR)
    if img is None:
        raise RuntimeError("Failed to decode PNG image")

    # Detect and decode QR Code
    detector = cv2.QRCodeDetector()
    decoded_text, points, _ = detector.detectAndDecode(img)
    print(f"[*] QR Code raw text: {decoded_text}")

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    match = flag_pattern.search(decoded_text)
    if not match:
        raise ValueError(f"Flag pattern not matched in decoded QR text: {decoded_text}")

    flag = match.group(0)
    print(f"[+] Flag found: {flag}")

    flag_file = Path(__file__).resolve().parent / "flag.txt"
    flag_file.write_text(flag + "\n")
    print(f"[+] Saved flag to {flag_file}")

    return flag

if __name__ == "__main__":
    solve()
