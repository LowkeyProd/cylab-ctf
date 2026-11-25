# Writeup: endianness

## Header & Metadata
- **Challenge:** endianness (ID: 414)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `nc xebec.cylabacademy.net 29984`
- **Attached Files:** flag.c
- **Official Flag:** `academy{3ndi4n_sw4p_su33ess_5da2acc3}`

---

## Mô tả bài toán (Overview / Analysis)
Know of little and big endian?

<a href='https://challenge-files.cylabacademy.net/library/d0e5a23c583ee9bba2ad6da69bfd03b5b5204fd956cac139a9a587116e653240/flag.c' download>Source</a>

### Hints
- You might want to check the ASCII table to first find the hexadecimal representation of characters before finding the endianness.
- Read  more about how endianness [ here](https://levelup.gitconnected.com/little-endian-and-big-endian-74ab6441b2a7 )

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via Antigravity following writeup instructions.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
import re
import socket
from pathlib import Path

def get_target_conn():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = "xebec.cylabacademy.net", 18506
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("HOST="):
                host = line.split("=", 1)[1].strip()
            elif line.startswith("PORT=") and line.split("=", 1)[1]:
                try:
                    port = int(line.split("=", 1)[1].strip())
                except Exception:
                    pass
    return host, port

def find_little_endian(word: str) -> str:
    return "".join(f"{ord(c):02X}" for c in reversed(word))

def find_big_endian(word: str) -> str:
    return "".join(f"{ord(c):02X}" for c in word)

class SocketHelper:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = ""

    def recv_until(self, delimiter: str, timeout: float = 10.0) -> str:
        self.sock.settimeout(timeout)
        while delimiter not in self.buf:
            chunk = self.sock.recv(4096).decode("latin-1")
            if not chunk:
                break
            self.buf += chunk
            print(chunk, end="", flush=True)
        idx = self.buf.find(delimiter)
        if idx != -1:
            res = self.buf[:idx + len(delimiter)]
            self.buf = self.buf[idx + len(delimiter):]
            return res
        res = self.buf
        self.buf = ""
        return res

    def recv_remaining(self, timeout: float = 5.0) -> str:
        self.sock.settimeout(timeout)
        res = self.buf
        self.buf = ""
        while True:
            try:
                chunk = self.sock.recv(4096).decode("latin-1")
                if not chunk:
                    break
                res += chunk
                print(chunk, end="", flush=True)
            except socket.timeout:
                break
        return res

def main():
    host, port = get_target_conn()
    print(f"[*] Connecting to {host}:{port}...", flush=True)

    with socket.create_connection((host, port), timeout=10) as s:
        sh = SocketHelper(s)
        
        # 1. Wait for "Word: "
        sh.recv_until("Word: ")
        
        # 2. Extract word up to newline
        word_line = sh.recv_until("\n")
        word = word_line.strip()
        print(f"\n[*] Extracted word: {word}", flush=True)

        le = find_little_endian(word)
        be = find_big_endian(word)
        print(f"[*] Calculated Little Endian: {le}", flush=True)
        print(f"[*] Calculated Big Endian: {be}", flush=True)

        # 3. Wait for Little Endian prompt
        sh.recv_until("Enter the Little Endian representation: ")
        print(f"[Sending LE]: {le}", flush=True)
        s.sendall((le + "\n").encode())

        # 4. Wait for Big Endian prompt
        sh.recv_until("Enter the Big Endian representation: ")
        print(f"[Sending BE]: {be}", flush=True)
        s.sendall((be + "\n").encode())

        # 5. Receive remainder
        remainder = sh.recv_remaining()

        # Find flag
        matches = re.findall(r"(?:picoCTF|academy)\{[^}]+\}", remainder)
        valid_flags = []
        for flag in matches:
            lowered = flag.lower()
            if any(decoy in lowered for decoy in ["decoy", "fake", "honeypot", "dummy"]):
                continue
            valid_flags.append(flag)

        if valid_flags:
            flag = valid_flags[0]
            print(f"\n[+] Flag retrieved: {flag}", flush=True)
            flag_file = Path(__file__).resolve().parent / "flag.txt"
            flag_file.write_text(flag)
            print(f"[+] Saved flag to {flag_file}", flush=True)
        else:
            print("\n[-] No flag found in output", flush=True)

if __name__ == "__main__":
    main()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{3ndi4n_sw4p_su33ess_5da2acc3}
```
