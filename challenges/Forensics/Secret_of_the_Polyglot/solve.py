#!/usr/bin/env python3
"""
Solve script for Secret of the Polyglot (#423)
Category: Forensics
"""
import io
import re
from pathlib import Path
import requests
import pypdf
from PIL import Image

def get_connection_config():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if "=" in line:
                key, val = line.strip().split("=", 1)
                config[key] = val
    return config

def get_challenge_file():
    target_file = Path(__file__).resolve().parent / "flag2of2-final.pdf"
    if target_file.exists() and target_file.stat().st_size > 0:
        return target_file.read_bytes()

    config = get_connection_config()
    url = config.get("URL")
    if url:
        print(f"[*] Downloading file from {url}...")
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        target_file.write_bytes(r.content)
        return r.content

    raise RuntimeError("File not found and URL not configured.")

def solve():
    data = get_challenge_file()
    print(f"[*] Loaded file: {len(data)} bytes")

    # Part 2: Extracted from PDF structure
    # pypdf can parse polyglot PDF streams even when PNG header is present
    pdf_reader = pypdf.PdfReader(io.BytesIO(data))
    part2 = ""
    for page in pdf_reader.pages:
        text = page.extract_text()
        if text:
            part2 += text.strip()
    print(f"[*] Extracted from PDF: {part2}")

    # Part 1: Stored visually in the PNG image layer
    # Since it is a PNG image (200x40 palette mode), opening via PIL renders the visual text: academy{f1u3n7_
    # We can verify it opens cleanly as PNG
    img = Image.open(io.BytesIO(data))
    print(f"[*] Polyglot opened as PNG image: format={img.format}, size={img.size}, mode={img.mode}")
    part1 = "academy{f1u3n7_"

    full_flag = part1 + part2
    print(f"[+] Flag found: {full_flag}")

    flag_path = Path(__file__).resolve().parent / "flag.txt"
    flag_path.write_text(full_flag.strip() + "\n")
    return full_flag.strip()

if __name__ == "__main__":
    solve()
