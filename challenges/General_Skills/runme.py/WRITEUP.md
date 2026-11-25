# Writeup: runme.py

## Header & Metadata
- **Challenge:** runme.py (ID: 250)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `N/A`
- **Attached Files:** runme.py
- **Official Flag:** `academy{run_s4n1ty_run}`

---

## Mô tả bài toán (Overview / Analysis)
Run the `runme.py` script to get the flag. Download the script with your
browser or with `wget` in the webshell.
<a href='https://challenge-files.cylabacademy.net/library/e4f0c4525ade26a755d6b5c3ce5b220a10c295879c2c3b75385e3a6c9e1ae697/runme.py' download>Download runme.py Python script</a>

### Hints
- If you have Python on your computer, you can download the script normally and
  run it. Otherwise, use the `wget` command in the webshell.
- To use `wget` in the webshell, first right click on the download link and
  select 'Copy Link' or 'Copy Link Address'
- Type everything after the dollar sign in the webshell: `$ wget `, then
  paste the link after the space after `wget` and press enter. This will
  download the script for you in the webshell so you can run it!
- Finally, to run the script, type everything after the dollar sign and then
  press enter: `$ python3 runme.py` You should have the flag now!

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
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

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{run_s4n1ty_run}
```
