#!/usr/bin/env python3
"""
Solve script for Mr-Worldwide (#40)
Category: Cryptography
"""
import re
from pathlib import Path
import requests

def get_target_url():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            if line.startswith("URL=") and line.strip().split("=", 1)[1]:
                return line.strip().split("=", 1)[1]
    return None

# Known coordinate mappings for the challenge
CITY_MAP = {
    (35.028309, 135.753082): ("Kyoto", "K"),
    (46.469391, 30.740883): ("Odessa", "O"),
    (39.758949, -84.191605): ("Dayton", "D"),
    (41.015137, 28.979530): ("Istanbul", "I"),
    (24.466667, 54.366669): ("Abu Dhabi", "A"),
    (3.140853, 101.693207): ("Kuala Lumpur", "K"),
    (9.005401, 38.763611): ("Addis Ababa", "A"),
    (-3.989038, -79.203560): ("Loja", "L"),
    (52.377956, 4.897070): ("Amsterdam", "A"),
    (41.085651, -73.858467): ("Sleepy Hollow", "S"),
    (57.790001, -152.407227): ("Kodiak", "K"),
    (31.205753, 29.924526): ("Alexandria", "A"),
}

def match_coord(lat, lon):
    for (clat, clon), (city, letter) in CITY_MAP.items():
        if abs(lat - clat) < 0.01 and abs(lon - clon) < 0.01:
            return city, letter
    return None, None

def solve():
    base_dir = Path(__file__).resolve().parent
    msg_file = base_dir / "message.txt"
    content = ""

    if msg_file.exists():
        content = msg_file.read_text(encoding="utf-8").strip()
    else:
        url = get_target_url()
        if url:
            print(f"[*] Downloading message from: {url}", flush=True)
            r = requests.get(url, timeout=10)
            content = r.text.strip()
            msg_file.write_text(content, encoding="utf-8")

    print(f"[*] Raw message: {content}", flush=True)

    prefix_match = re.match(r'^([a-zA-Z0-9_]+)\{(.*)\}$', content)
    if not prefix_match:
        print("[-] Invalid format", flush=True)
        return None

    prefix = prefix_match.group(1)
    body = prefix_match.group(2)

    parts = body.split("_")
    decoded_words = []

    for part in parts:
        coords = re.findall(r'\(\s*([-\d\.]+)\s*,\s*([-\d\.]+)\s*\)', part)
        word = ""
        for lat_s, lon_s in coords:
            lat, lon = float(lat_s), float(lon_s)
            city, letter = match_coord(lat, lon)
            if letter:
                print(f"[+] ({lat}, {lon}) -> {city} -> {letter}", flush=True)
                word += letter
            else:
                print(f"[-] Unknown coord: ({lat}, {lon})", flush=True)
                word += "?"
        decoded_words.append(word)

    decoded_body = "_".join(decoded_words)
    flag = f"{prefix}{{{decoded_body}}}"
    print(f"[+] Flag found: {flag}", flush=True)

    flag_file = base_dir / "flag.txt"
    flag_file.write_text(flag + "\n", encoding="utf-8")
    return flag

if __name__ == "__main__":
    solve()
