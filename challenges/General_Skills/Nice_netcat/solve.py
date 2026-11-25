import socket
import re
import os

def get_connection_info():
    host = "chatelaine.cylabacademy.net"
    port = 21524
    cfg_path = os.path.join(os.path.dirname(__file__), "connection.cfg")
    if os.path.exists(cfg_path):
        with open(cfg_path, "r") as f:
            for line in f:
                line = line.strip()
                if line.startswith("HOST="):
                    host = line.split("=", 1)[1].strip()
                elif line.startswith("PORT="):
                    port = int(line.split("=", 1)[1].strip())
    return host, port

def solve():
    host, port = get_connection_info()
    print(f"Connecting to {host}:{port}...", flush=True)
    
    data = b""
    with socket.create_connection((host, port), timeout=15) as s:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            
    raw_text = data.decode("utf-8", errors="ignore")
    print(f"Received raw data:\n{raw_text}", flush=True)
    
    numbers = raw_text.split()
    chars = [chr(int(n)) for n in numbers if n.isdigit()]
    decoded = "".join(chars)
    print(f"Decoded message: {decoded}", flush=True)
    
    match = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", decoded)
    if not match:
        raise ValueError(f"Flag pattern not found in decoded text: {decoded}")
        
    flag = match.group(1).strip()
    
    decoys = ["decoy", "fake", "honeypot", "dummy"]
    if any(d in flag.lower() for d in decoys):
        raise ValueError(f"Flag rejected as decoy: {flag}")
        
    print(f"Found flag: {flag}", flush=True)
    
    flag_path = os.path.join(os.path.dirname(__file__), "flag.txt")
    with open(flag_path, "w") as f:
        f.write(flag + "\n")
        
    print(f"Flag saved to {flag_path}", flush=True)
    return flag

if __name__ == "__main__":
    solve()
