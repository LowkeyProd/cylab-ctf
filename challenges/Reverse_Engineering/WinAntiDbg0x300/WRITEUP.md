# Writeup: WinAntiDbg0x300

## Header & Metadata
- **Challenge:** WinAntiDbg0x300 (ID: 431)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering
- **Server / Instance:** `N/A`
- **Attached Files:** WinAntiDbg0x300.zip
- **Official Flag:** `academy{Wind0ws_antid3bg_0x300_1415757f}`

---

## Mô tả bài toán (Overview / Analysis)
This challenge is a little bit invasive. It will try to fight your debugger. With that in mind, debug the binary and get the flag!

This challenge executable is a GUI application and it requires admin privileges. And remember, the flag might get corrupted if you mess up the process's state.

Challenge can be downloaded <a href='https://challenge-files.cylabacademy.net/library/7a816a670d776e829de097d66432ea9a56d10385e37064193add756827163954/WinAntiDbg0x300.zip' download>here</a>. Unzip
the archive with the password `academy`

If you get "VCRUNTIME140D.dll" and "ucrtbased.dll" missing error, then that
means the Universal C Runtime library and Visual C++ Debug library are not
installed on your Windows machine.

The quickest way to fix this is:

- Download Visual Studio Community installer from
  https://visualstudio.microsoft.com/vs/community/

- After the installer starts, first select 'Desktop development with C++' and
  then, in the right side column, select 'MSVC v143 - VS 2022 C++ x64/x86 build
  tools' and 'Windows 11 SDK' packages.

This will take ~30 mins to install any missing DLLs.


### Hints
- There is an infinite loop to constantly check for the debugger.
- Get past that infinite loop. Maybe 'Patch' the binary to jump to the appropriate location?
- If you've done everything correctly, the flag should pop-up on your screen after 5 seconds of launching the program. The flag will also be printed to the Debug output to make it easy for you to copy the flag to the clipboard. See 'DebugView' program in Sysinternals Suite.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
import os
import sys

def read_connection_cfg(cfg_path="connection.cfg"):
    cfg = {}
    if os.path.exists(cfg_path):
        with open(cfg_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    return cfg

def popcount(n):
    return bin(n).count("1")

def compute_hash_round(buf):
    new_buf = list(buf)
    for i in range(len(buf)):
        pop = popcount(i % 255)
        new_buf[i] = ord('a') + ((new_buf[i] - ord('a') + pop) % 26)
    return new_buf

def solve():
    print("[*] Reading target configuration...", flush=True)
    cfg = read_connection_cfg()
    print(f"[*] Configuration: {cfg}", flush=True)

    config_path = "config.bin"
    if not os.path.exists(config_path):
        # Check if zip exists
        if os.path.exists("WinAntiDbg0x300.zip"):
            import zipfile
            print("[*] Extracting WinAntiDbg0x300.zip...", flush=True)
            with zipfile.ZipFile("WinAntiDbg0x300.zip") as z:
                z.extractall(pwd=b"academy")

    print("[*] Reading config.bin...", flush=True)
    with open(config_path, "rb") as f:
        data = f.read()

    length = int.from_bytes(data[:4], "little")
    p1 = list(data[4 : 4 + length])
    # separator is 1 byte at index 4 + length
    p2 = list(data[4 + length + 1 : 4 + length + 1 + length])

    print(f"[*] Config length: {length}", flush=True)
    print(f"[*] Initial buffer (p1): {bytes(p1).decode('ascii', errors='replace')}", flush=True)

    # From static analysis:
    # 1. wWinMain: ComputeHash(3) -> 3 rounds
    # 2. wWinMain: ComputeHash(2) -> 2 rounds
    # 3. wWinMain: ComputeHash(2) -> 2 rounds
    # 4. ManageChild/Mutex: ComputeHash(1) -> 1 round
    # 5. Mutex not existing: ComputeHash(1) -> 1 round
    # 6. ThreadProc: ComputeHash(2) -> 2 rounds
    # 7. ThreadProc (post-loop): ComputeHash(1) -> 1 round
    # Total = 3 + 2 + 2 + 1 + 1 + 2 + 1 = 12 rounds
    cur = list(p1)
    target_rounds = 12

    for r in range(target_rounds):
        cur = compute_hash_round(cur)

    flag_bytes = bytes([b ^ k for b, k in zip(p2, cur)])
    flag = flag_bytes.decode("ascii")

    print(f"[+] Flag found: {flag}", flush=True)

    # Save to flag.txt
    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag.strip() + "\n")
    print("[+] Saved flag to flag.txt", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{Wind0ws_antid3bg_0x300_1415757f}
```
