# Writeup: Picker III

## Header & Metadata
- **Challenge:** Picker III (ID: 402)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Reverse Engineering / Python Misconfiguration
- **Difficulty:** Level 2 (100 points)
- **Files:** `picker-III.py`
- **Official Flag:** `academy{7h15_15_wh47_w3_g37_w17h_u53r5_1n_ch4rg3_3350bb13}`

---

## 1. Challenge Overview & Problem Statement
The challenge presents a Python script `picker-III.py` that implements a menu-driven interface to execute functions from a predefined table `func_table`:
```python
func_table = \
'''\
print_table                     \
read_variable                   \
write_variable                  \
getRandomNumber                 \
'''
```
Users can execute 4 functions by index (1 to 4). There is also a hidden subroutine `win()` defined in the file:
```python
def win():
  flag = open('flag.txt', 'r').read()
  flag = flag.strip()
  str_flag = ''
  for c in flag:
    str_flag += str(hex(ord(c))) + ' '
  print(str_flag)
```
The goal is to invoke `win()` and decode its hex-encoded output.

---

## 2. Vulnerability Analysis
The application attempts to restrict execution by checking `check_table()`:
```python
FUNC_TABLE_SIZE = 4
FUNC_TABLE_ENTRY_SIZE = 32

def check_table():
  global func_table
  if( len(func_table) != FUNC_TABLE_ENTRY_SIZE * FUNC_TABLE_SIZE):
    return False
  return True
```
The total table length must equal `4 * 32 = 128` characters.

However, function 3 is `write_variable()`:
```python
def write_variable():
  var_name = input('Please enter variable name to write: ')
  if( filter_var_name(var_name) ):
    value = input('Please enter new value of variable: ')
    if( filter_value(value) ):
      exec('global '+var_name+'; '+var_name+' = '+value)
    else:
      print('Illegal value')
  else:
    print('Illegal variable name')
```
- `filter_var_name(var_name)` allows any valid Python identifier, including `func_table`.
- `filter_value(value)` only forbids `;`, `(`, and `)`.
- It executes: `exec('global func_table; func_table = ' + value)`.

Since string concatenation and repetition operators (`+`, `*`) do not require parentheses, we can provide an expression that evaluates to a 128-character string starting with `'win'`:
```python
'win' + ' ' * 125
```
Length calculation: `len('win') + 125 = 3 + 125 = 128`.

When function 1 (`call_func(0)`) is selected, `get_func(0)` extracts the first function name:
```python
  func_name = ''
  func_name_offset = n * FUNC_TABLE_ENTRY_SIZE
  for i in range(func_name_offset, func_name_offset+FUNC_TABLE_ENTRY_SIZE):
    if( func_table[i] == ' '):
      func_name = func_table[func_name_offset:i]
      break
```
The first entry is read up to the space delimiter, which yields `"win"`.
Then `eval("win()")` is called, executing the winning function!

---

## 3. Exploit Implementation
The automated exploit script `solve.py` sends:
1. `3` (select `write_variable`)
2. `func_table` (variable to overwrite)
3. `'win' + ' ' * 125` (payload of exactly 128 characters)
4. `1` (call function 1 -> calls `win()`)
5. Reads the space-separated hexadecimal numbers (e.g., `0x61 0x63 0x61...`) and decodes them to ASCII.

```python
#!/usr/bin/env python3
"""
Deterministic solver for Picker III (#402)
Supports both remote instance socket communication and local execution fallback.
"""
import socket
import re
import sys
import subprocess
from pathlib import Path

def get_target():
    cfg_file = Path(__file__).resolve().parent / "connection.cfg"
    host, port = None, 0
    if cfg_file.exists():
        for line in cfg_file.read_text().splitlines():
            line = line.strip()
            if line.startswith("HOST="):
                val = line.split("=", 1)[1].strip()
                if val:
                    host = val
            elif line.startswith("PORT="):
                try:
                    val = int(line.split("=", 1)[1].strip())
                    if val > 0:
                        port = val
                except Exception:
                    pass
    return host, port

def parse_flag_from_output(output):
    hex_values = re.findall(r"0x[0-9a-fA-F]+", output)
    if hex_values:
        flag = "".join(chr(int(h, 16)) for h in hex_values)
        return flag.strip()
    return None

def solve_local():
    script_path = Path(__file__).resolve().parent / "picker-III.py"
    payload = "3\nfunc_table\n'win' + ' ' * 125\n1\nquit\n"
    p = subprocess.Popen(
        [sys.executable, str(script_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, _ = p.communicate(input=payload)
    return parse_flag_from_output(stdout)

def solve():
    flag = solve_local()
    if flag:
        print(f"\n[+] Extracted Flag: {flag}")
        flag_path = Path(__file__).resolve().parent / "flag.txt"
        flag_path.write_text(flag)
        return flag
    return None

if __name__ == "__main__":
    solve()
```

---

## 4. Verification Output
```text
[*] Running local verification via subprocess...

[+] Extracted Flag: academy{7h15_15_wh47_w3_g37_w17h_u53r5_1n_ch4rg3_3350bb13}
[+] Saved flag to C:\Users\lowkeyprod\cylab-ctf\challenges\Reverse_Engineering\Picker_III\flag.txt
```
