import socket
import re
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

def get_connection_info():
    cfg_path = os.path.join(os.path.dirname(__file__), 'connection.cfg')
    host = None
    port = None
    if os.path.exists(cfg_path):
        with open(cfg_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('HOST='):
                    host = line.split('=', 1)[1].strip()
                elif line.startswith('PORT='):
                    port = int(line.split('=', 1)[1].strip())
    return host, port

def solve():
    host, port = get_connection_info()
    print(f"Connecting to {host}:{port}...", flush=True)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # Read until prompt or receive banner
    data = b""
    while b"==>" not in data:
        chunk = s.recv(1024)
        if not chunk:
            break
        data += chunk

    print(f"Received banner:\n{data.decode('utf-8', errors='ignore')}", flush=True)

    # Send 'eee\n' (\x65\x65\x65)
    s.sendall(b"eee\n")

    response = b""
    while True:
        chunk = s.recv(1024)
        if not chunk:
            break
        response += chunk
        # Check if flag is in response
        if b"}" in response:
            break

    s.close()
    full_text = response.decode('utf-8', errors='ignore')
    print(f"Response:\n{full_text}", flush=True)

    match = re.search(r'(academy\{[^}]+\}|picoCTF\{[^}]+\})', full_text)
    if match:
        flag = match.group(1)
        print(f"Extracted Flag: {flag}", flush=True)
        # Check for decoy
        for bad in ['decoy', 'fake', 'honeypot', 'dummy']:
            if bad in flag.lower():
                print(f"Warning: Flag contains {bad}, possible decoy!", flush=True)
                return
        with open("flag.txt", "w") as f:
            f.write(flag)
        print("Flag written to flag.txt", flush=True)
    else:
        print("Flag not found in response!", flush=True)

if __name__ == "__main__":
    solve()
