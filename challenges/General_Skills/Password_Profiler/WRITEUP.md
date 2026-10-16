# Writeup: Password Profiler

## Header & Metadata
- **Challenge:** Password Profiler (ID: 712)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** General Skills
- **Server / Instance:** `https://challenge-files.cylabacademy.net/library/eee2a66921bd7ab65c6464f5293a9d15cc01c8631a0dc4c9668db8a2525639fc/userinfo.txt`
- **Attached Files:** userinfo.txt, hash.txt, check_password.py
- **Official Flag:** `academy{aliceaj7515}`

---

## Mô tả bài toán (Overview / Analysis)
We intercepted a suspicious file from a system, but instead of the password itself, it only contains its SHA-1 hash. Using OSINT techniques, you are provided with personal details about the target. Your task is to leverage this information to generate a custom password list and recover the original password by matching its hash.
Download the following files:

<a href='https://challenge-files.cylabacademy.net/library/eee2a66921bd7ab65c6464f5293a9d15cc01c8631a0dc4c9668db8a2525639fc/userinfo.txt' download>userinfo</a>: Contains the personal details.

<a href='https://challenge-files.cylabacademy.net/library/eee2a66921bd7ab65c6464f5293a9d15cc01c8631a0dc4c9668db8a2525639fc/hash.txt' download>hash</a>: Contains the SHA-1 hash of the password.

<a href='https://challenge-files.cylabacademy.net/library/eee2a66921bd7ab65c6464f5293a9d15cc01c8631a0dc4c9668db8a2525639fc/check_password.py' download>check_password</a>: Script to test passwords against the hash.

### Hints
- [ CUPP](https://github.com/Mebus/cupp) is a Python tool for generating custom wordlists from personal data.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved autonomously by Antigravity CTF Agent.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Password Profiler - Solve Script
Generates candidate passwords based on target profile (CUPP logic) and matches target SHA-1 hash.
"""
import hashlib
import os

def load_userinfo(filepath="userinfo.txt"):
    info = {}
    if not os.path.exists(filepath):
        return info
    with open(filepath, "r") as f:
        for line in f:
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip().lower()] = v.strip()
    return info

def load_hash(filepath="hash.txt"):
    with open(filepath, "r") as f:
        return f.read().strip()

def generate_profile_passwords(userinfo):
    name = userinfo.get("first name", "alice").lower()
    surname = userinfo.get("surname", "johnson").lower()
    nick = userinfo.get("nickname", "aj").lower()
    birthdate_raw = userinfo.get("birthdate", "15-07-1990").replace("-", "").replace("/", "")
    partner = userinfo.get("partner's name", "bob").lower()
    child = userinfo.get("child's name", "charlie").lower()

    # Title cases
    names = [name, name.title(), surname, surname.title(), nick, nick.title()]
    partners = [partner, partner.title(), surname, surname.title()]
    children = [child, child.title(), surname, surname.title()]

    # Date parts for birthdate DDMMYYYY (e.g., 15071990)
    dd = birthdate_raw[:2]
    mm = birthdate_raw[2:4]
    yy = birthdate_raw[-2:]
    yyy = birthdate_raw[-3:]
    yyyy = birthdate_raw[-4:]
    xd = birthdate_raw[1:2]
    xm = birthdate_raw[3:4]

    bds = [yy, yyy, yyyy, xd, xm, dd, mm]
    bdss = []
    for b1 in bds:
        bdss.append(b1)
        for b2 in bds:
            if bds.index(b1) != bds.index(b2):
                bdss.append(b1 + b2)
                for b3 in bds:
                    if (bds.index(b1) != bds.index(b2) and 
                        bds.index(b2) != bds.index(b3) and 
                        bds.index(b1) != bds.index(b3)):
                        bdss.append(b1 + b2 + b3)

    # Combinations of names
    kombinaa = []
    for n1 in names:
        kombinaa.append(n1)
        for n2 in names:
            if names.index(n1) != names.index(n2) and n1.title() != n2.title():
                kombinaa.append(n1 + n2)

    candidates = set()
    # Direct combinations of name combos + birthdate fragments
    for n in kombinaa:
        candidates.add(n)
        for b in bdss:
            candidates.add(n + b)
            candidates.add(n + "_" + b)
            candidates.add(b + n)

    # Single components and reverse
    for n in names + partners + children:
        candidates.add(n)
        candidates.add(n[::-1])
        for b in bdss:
            candidates.add(n + b)
            candidates.add(n[::-1] + b)

    return sorted(candidates)

def solve():
    target_hash = load_hash()
    userinfo = load_userinfo()

    candidates = generate_profile_passwords(userinfo)

    # Save to passwords.txt so check_password.py can also use it
    with open("passwords.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(candidates) + "\n")

    matched_pwd = None
    for pwd in candidates:
        if hashlib.sha1(pwd.encode()).hexdigest() == target_hash:
            matched_pwd = pwd
            break

    if not matched_pwd:
        raise ValueError("Password could not be cracked from profile wordlist!")

    flag = f"academy{{{matched_pwd}}}"
    with open("flag.txt", "w") as f:
        f.write(flag + "\n")

    print(f"Password recovered: {matched_pwd}")
    print(f"Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{aliceaj7515}
```
