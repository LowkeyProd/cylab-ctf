# Writeup: Binary Search

## Header & Metadata
- **Challenge:** Binary Search (ID: 442)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `https://challenge-files.cylabacademy.net/library/5cacbfdfbd3d335ddab68f2fbd660af0eb6d8d62564697282264b5296cd0b294/challenge.zip`
- **Attached Files:** challenge.zip
- **Official Flag:** `academy{g00d_gu355_1b252bff}`

---

## Mô tả bài toán (Overview / Analysis)
Want to play a game? As you use more of the shell, you might be interested in how they work! Binary search is a classic algorithm used to quickly find an item in a sorted list. Can you find the flag? You'll have 1000 possibilities and only 10 guesses.

Cyber security often has a huge amount of data to look through - from logs, vulnerability reports, and forensics. Practicing the fundamentals manually might help you in the future when you have to write your own tools!

You can download the challenge files here:

- <a href='https://challenge-files.cylabacademy.net/library/5cacbfdfbd3d335ddab68f2fbd660af0eb6d8d62564697282264b5296cd0b294/challenge.zip' download>challenge.zip</a>
`ssh -p 26888 ctf-player@xebec.cylabacademy.net`

Using the password `647e170e`. Accept the fingerprint with `yes`; the game starts as soon as you are connected. Remember, in a shell, passwords are hidden!

### Hints
- Have you ever played hot or cold? Binary search is a bit like that.
- You have a very limited number of guesses. Try larger jumps between numbers!
- The program will randomly choose a new number each time you connect. You can always try again, but you should start your binary search over from the beginning - try around 500. Can you think of why?

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Binary Search (#442)
Category: General Skills
"""
import re
import sys
import time
from pathlib import Path
import paramiko

def read_config():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    if cfg_file.exists():
        for line in cfg_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()

    # Fallback to info.json if connection.cfg has placeholder or missing SSH info
    info_file = Path(__file__).resolve().parent / "info.json"
    if info_file.exists():
        import json
        try:
            info_data = json.loads(info_file.read_text(encoding="utf-8"))
            desc = info_data.get("description", "")
            ssh_m = re.search(r'ssh\s+-p\s+(\d+)\s+([^@]+)@([^\s`]+)', desc)
            pass_m = re.search(r'password\s+`?([a-zA-Z0-9]+)`?', desc, re.IGNORECASE)
            
            # If config host is file server or missing SSH details, use parsed details
            if "challenge-files" in config.get("HOST", "") or "SSH_USER" not in config:
                if ssh_m:
                    config["PORT"] = int(ssh_m.group(1))
                    config["SSH_USER"] = ssh_m.group(2)
                    config["HOST"] = ssh_m.group(3)
                if pass_m:
                    config["SSH_PASS"] = pass_m.group(1)
        except Exception as e:
            print(f"[-] Warning parsing info.json: {e}", flush=True)

    return config

def is_valid_flag(flag: str) -> bool:
    decoys = ['decoy', 'fake', 'honeypot', 'dummy', 'not_the_flag']
    return not any(d in flag.lower() for d in decoys)

def solve():
    config = read_config()
    host = config.get("HOST", "xebec.cylabacademy.net")
    port = int(config.get("PORT", 26888))
    user = config.get("SSH_USER", "ctf-player")
    password = config.get("SSH_PASS", "")

    print(f"[*] Connecting to {user}@{host}:{port}...", flush=True)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        client.connect(host, port=port, username=user, password=password, timeout=15)
        channel = client.invoke_shell()
        channel.settimeout(10.0)
    except Exception as e:
        print(f"[-] SSH connection failed: {e}", flush=True)
        return None

    low = 1
    high = 1000
    guess_count = 0
    last_guess = None
    buffer = ""
    flag = None

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')

    start_time = time.time()
    while time.time() - start_time < 30:
        if channel.recv_ready():
            chunk = channel.recv(4096).decode("utf-8", errors="ignore")
            buffer += chunk
            sys.stdout.write(chunk)
            sys.stdout.flush()

            # Check for flag in buffer
            matches = flag_pattern.findall(buffer)
            for m in matches:
                if is_valid_flag(m):
                    flag = m
                    break
            if flag:
                break

            # Check if prompt is waiting for input
            if "Enter your guess:" in buffer:
                # Determine response to previous guess from buffer before clearing
                if "Higher!" in buffer:
                    # Previous guess was too low
                    # (already handled after sending or handled here)
                    pass
                buffer_lines = buffer.splitlines()
                # Find the latest clue
                for line in reversed(buffer_lines):
                    if "Higher!" in line:
                        low = last_guess + 1
                        break
                    elif "Lower!" in line:
                        high = last_guess - 1
                        break

                mid = (low + high) // 2
                guess_count += 1
                last_guess = mid
                print(f"\n[*] [Guess #{guess_count}] Range: [{low}, {high}] -> Guessing: {mid}", flush=True)
                channel.send(f"{mid}\n")
                buffer = ""  # Reset buffer after replying to prompt
        else:
            time.sleep(0.05)

    client.close()

    if flag:
        print(f"\n[+] Flag recovered: {flag}", flush=True)
        flag_file = Path(__file__).resolve().parent / "flag.txt"
        flag_file.write_text(flag.strip() + "\n", encoding="utf-8")
        return flag
    else:
        print("\n[-] Flag not found.", flush=True)
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{g00d_gu355_1b252bff}
```
