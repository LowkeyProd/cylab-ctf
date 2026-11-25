#!/usr/bin/env python3
"""
Solve script for Enhance! (#265)
Category: Forensics
"""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

def get_connection_info():
    config_file = Path("connection.cfg")
    config = {}
    if config_file.exists():
        for line in config_file.read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def solve():
    print("[*] Solving Enhance!...", flush=True)
    _cfg = get_connection_info()
    
    svg_path = Path("drawing.flag.svg")
    if not svg_path.exists():
        raise FileNotFoundError("drawing.flag.svg not found")
        
    tree = ET.parse(svg_path)
    root = tree.getroot()
    
    # Extract text from all tspan elements
    tspans = root.findall(".//{http://www.w3.org/2000/svg}tspan")
    extracted_text = "".join(t.text for t in tspans if t.text is not None)
    cleaned_text = re.sub(r"\s+", "", extracted_text)
    
    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", cleaned_text)
    if not match:
        raise ValueError(f"Flag pattern not found in cleaned text: {cleaned_text}")
        
    flag = match.group(1)
    
    # Reject decoy flags
    for decoy in ['decoy', 'fake', 'honeypot', 'dummy']:
        if decoy in flag.lower():
            raise ValueError(f"Decoy flag rejected: {flag}")
            
    print(f"[+] Flag found: {flag}", flush=True)
    
    flag_file = Path("flag.txt")
    flag_file.write_text(flag)
    print(f"[+] Flag written to {flag_file.resolve()}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
