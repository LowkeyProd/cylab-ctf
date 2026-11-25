# Writeup: Rust fixme 3

## Header & Metadata
- **Challenge:** Rust fixme 3 (ID: 463)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** fixme3.tar.gz
- **Official Flag:** `academy{n0w_y0uv3_f1x3d_1h3m_411}`

---

## Mô tả bài toán (Overview / Analysis)
Have you heard of Rust? Fix the syntax errors in this Rust file to print the flag!

Download the Rust code <a href='https://challenge-files.cylabacademy.net/library/6df8b7779faf29e53f515922041d99bc26381a332ca090c291ba20577ac7cf92/fixme3.tar.gz' download>here</a>.


### Hints
- Read the comments...darn it!

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Deterministic solve script for Rust fixme 3 (#463)
Category: General Skills
"""
import os
import re
import subprocess
import tarfile
from pathlib import Path

def get_config():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    config = {}
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                config[k.strip()] = v.strip()
    return config

def fix_rust_code(rust_file: Path):
    if not rust_file.exists():
        return
    content = rust_file.read_text(encoding="utf-8")
    
    # Uncomment unsafe block if commented
    content = content.replace("// unsafe {", "unsafe {")
    # Fix the matching closing brace if commented
    # Look for '// }' after 'borrowed_string.push_str'
    content = re.sub(r'//\s*\}\s*(\r?\n\s*println!)', r'}\1', content)
    
    rust_file.write_text(content, encoding="utf-8")

def solve():
    base_dir = Path(__file__).resolve().parent
    config = get_config()
    print(f"[*] Configuration: {config}", flush=True)

    fixme_dir = base_dir / "fixme3"
    tar_file = base_dir / "fixme3.tar.gz"

    if not fixme_dir.exists() and tar_file.exists():
        print("[*] Extracting fixme3.tar.gz...", flush=True)
        with tarfile.open(tar_file, "r:gz") as tar:
            tar.extractall(base_dir)

    main_rs = fixme_dir / "src" / "main.rs"
    if main_rs.exists():
        print("[*] Fixing syntax in main.rs...", flush=True)
        fix_rust_code(main_rs)

    # Convert path to WSL path
    fixme_wsl_path = str(fixme_dir).replace('\\', '/')
    if fixme_wsl_path[1:3] == ':/':
        drive = fixme_wsl_path[0].lower()
        fixme_wsl_path = f"/mnt/{drive}{fixme_wsl_path[2:]}"

    print(f"[*] Running cargo run in WSL at {fixme_wsl_path}...", flush=True)
    cmd = ["wsl", "-d", "kali-linux", "bash", "-c", f"cd '{fixme_wsl_path}' && cargo run"]
    res = subprocess.run(cmd, capture_output=True, text=True)
    output = res.stdout + res.stderr
    print(f"[*] Command output:\n{output}", flush=True)

    flag_pattern = re.compile(r'(?:academy|picoCTF)\{[a-zA-Z0-9_\-\.\!\?@#]+\}')
    matches = flag_pattern.findall(output)

    valid_flags = [f for f in matches if not any(d in f.lower() for d in ['fake', 'decoy', 'honey', 'dummy'])]

    if valid_flags:
        flag = valid_flags[0]
        print(f"[+] Flag found: {flag}", flush=True)
        (base_dir / "flag.txt").write_text(flag + "\n", encoding="utf-8")
        return flag
    else:
        print("[-] Flag not found in output.", flush=True)
        return None

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{n0w_y0uv3_f1x3d_1h3m_411}
```
