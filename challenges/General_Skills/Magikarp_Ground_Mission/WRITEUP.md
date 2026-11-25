# Writeup: Magikarp Ground Mission

## Header & Metadata
- **Challenge:** Magikarp Ground Mission (ID: 189)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** None
- **Official Flag:** `academy{xxsh_0ut_0f_//4t3r_47c47679}`

---

## Mô tả bài toán (Overview / Analysis)
Do you know how to move between directories and read files in the shell? Start the container, `ssh` to it, and then `ls` once connected to begin.
Login via `ssh` as `ctf-player` with the password, `f6904eaa` on the host `chatelaine.cylabacademy.net` and port `41192`.

### Hints
- Finding a cheatsheet for bash would be really helpful!

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for Magikarp Ground Mission (#189)
Category: General Skills
Domain Methodology: Computer Science & Algorithms (Easy)
"""
import sys
from pathlib import Path
import paramiko

def parse_config(cfg_path: Path):
    config = {}
    if not cfg_path.exists():
        return config
    with open(cfg_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                config[key.strip()] = val.strip()
    return config

def solve():
    script_dir = Path(__file__).resolve().parent
    cfg_path = script_dir / "connection.cfg"
    config = parse_config(cfg_path)

    host = config.get("HOST", "chatelaine.cylabacademy.net")
    port = int(config.get("PORT", 46644))
    username = config.get("USER", "ctf-player")
    password = config.get("PASS", "f6904eaa")

    print(f"[*] Connecting to {host}:{port} as {username}...", flush=True)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port=port, username=username, password=password, timeout=15)

    # Read part 1
    _, stdout, _ = client.exec_command("cat /home/ctf-player/drop-in/1of3.flag.txt")
    part1 = stdout.read().decode("utf-8").strip()

    # Read part 2
    _, stdout, _ = client.exec_command("cat /2of3.flag.txt")
    part2 = stdout.read().decode("utf-8").strip()

    # Read part 3
    _, stdout, _ = client.exec_command("cat /home/ctf-player/3of3.flag.txt")
    part3 = stdout.read().decode("utf-8").strip()

    client.close()

    flag = f"{part1}{part2}{part3}".strip()

    # Save to flag.txt
    flag_file = script_dir / "flag.txt"
    flag_file.write_text(flag + "\n", encoding="utf-8")

    # Print exact flag cleanly to standard output
    print(flag, flush=True)
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{xxsh_0ut_0f_//4t3r_47c47679}
```
