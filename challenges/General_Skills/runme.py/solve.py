#!/usr/bin/env python3
import subprocess
import sys
import re
from pathlib import Path

def solve():
    script_dir = Path(__file__).resolve().parent
    runme_path = script_dir / "runme.py"
    flag_file = script_dir / "flag.txt"

    print(f"[*] Checking local script: {runme_path}", flush=True)

    flag = None
    if runme_path.exists():
        # Execute runme.py using sys.executable
        res = subprocess.run([sys.executable, str(runme_path)], capture_output=True, text=True)
        output = res.stdout + res.stderr
        print(f"[*] Script output:\n{output}", flush=True)

        matches = re.findall(r'(?:academy|picoCTF)\{[^}\s]+\}', output)
        for m in matches:
            if not any(decoy in m.lower() for decoy in ['fake', 'decoy', 'honey', 'not_the_flag', 'dummy']):
                flag = m
                break

    if not flag:
        # Fallback to reading file content directly
        content = runme_path.read_text(encoding="utf-8", errors="ignore")
        matches = re.findall(r'(?:academy|picoCTF)\{[^}\s]+\}', content)
        for m in matches:
            if not any(decoy in m.lower() for decoy in ['fake', 'decoy', 'honey', 'not_the_flag', 'dummy']):
                flag = m
                break

    if flag:
        print(f"[+] Flag found: {flag}", flush=True)
        flag_file.write_text(flag.strip() + "\n", encoding="utf-8")
        return flag
    else:
        print("[-] Flag not found!", flush=True)
        sys.exit(1)

if __name__ == "__main__":
    solve()
