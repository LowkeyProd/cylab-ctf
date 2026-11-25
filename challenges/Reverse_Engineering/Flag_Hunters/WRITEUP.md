# Writeup: Flag Hunters

## Header & Metadata
- **Challenge:** Flag Hunters (ID: 472)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `nc chatelaine.cylabacademy.net 43489`
- **Attached Files:** lyric-reader.py
- **Official Flag:** `academy{70637h3r_f0r3v3r_697ad4d5}`

---

## Mô tả bài toán (Overview / Analysis)
Lyrics jump from verses to the refrain kind of like a subroutine call. There's
a hidden refrain this program doesn't print by default. Can you get it to print
it? There might be something in it for you.

The program's source code can be downloaded
<a href='https://challenge-files.cylabacademy.net/library/659de58d4def8163cd0116c565d8900a309427071dc758473385f9468d93370f/lyric-reader.py' download>here</a>.
Connect to the program with netcat:

`$ nc chatelaine.cylabacademy.net 43489`

### Hints
- This program can easily get into undefined states. Don't be shy about Ctrl-C.
- Unsanitized user input is always good, right?
- Is there any syntax that is ripe for subversion?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
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

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{70637h3r_f0r3v3r_697ad4d5}
```
