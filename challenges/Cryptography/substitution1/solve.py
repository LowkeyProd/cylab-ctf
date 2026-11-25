#!/usr/bin/env python3
"""
Solve script for substitution1 (#308)
Category: Cryptography
"""
import re
import string
from pathlib import Path

def solve():
    print("[*] Solving substitution1...", flush=True)
    msg_path = Path(__file__).parent / "message.txt"
    if not msg_path.exists():
        raise FileNotFoundError(f"Message file not found at {msg_path}")

    ciphertext = msg_path.read_text(encoding="utf-8")

    # Known plaintext preamble
    known_cipher_preamble = (
        "RZFt (tquvz fuv rlwzbvp zqp felg) lvp l zcwp uf ruawbzpv tprbvnzc ruawpznznuo. "
        "Ruozptzlozt lvp wvptpozpx jnzq l tpz uf rqleepogpt jqnrq zptz zqpnv rvplznsnzc, "
        "zprqonrle (lox guugenog) tmneet, lox wvuhepa-tuesnog lhnenzc. "
        "Rqleepogpt btbleec ruspv l obahpv uf rlzpguvnpt, lox jqpo tuespx, "
        "plrq cnpext l tzvnog (rleepx l felg) jqnrq nt tbhanzzpx zu lo uoenop truvnog tpvsnrp. "
        "RZFt lvp l gvplz jlc zu eplvo l jnxp lvvlc uf ruawbzpv tprbvnzc tmneet no l tlfp, "
        "epgle posnvuoapoz, lox lvp qutzpx lox welcpx hc aloc tprbvnzc gvubwt lvubox zqp juvex "
        "fuv fbo lox wvlrznrp. Fuv zqnt wvuhepa, zqp felg nt: "
    )

    known_plain_preamble = (
        "CTFs (short for capture the flag) are a type of computer security competition. "
        "Contestants are presented with a set of challenges which test their creativity, "
        "technical (and googling) skills, and problem-solving ability. "
        "Challenges usually cover a number of categories, and when solved, "
        "each yields a string (called a flag) which is submitted to an online scoring service. "
        "CTFs are a great way to learn a wide array of computer security skills in a safe, "
        "legal environment, and are hosted and played by many security groups around the world "
        "for fun and practice. For this problem, the flag is: "
    )

    mapping = {}
    for c_char, p_char in zip(known_cipher_preamble, known_plain_preamble):
        if c_char.isalpha():
            mapping[c_char.lower()] = p_char.lower()

    # D in cipher corresponds to Q in plaintext (FR3QU3NCY from FV3DB3ORC)
    mapping['d'] = 'q'

    decrypted = []
    for ch in ciphertext:
        if ch.islower():
            decrypted.append(mapping.get(ch, ch))
        elif ch.isupper():
            decrypted.append(mapping.get(ch.lower(), ch.lower()).upper())
        else:
            decrypted.append(ch)

    decrypted_text = "".join(decrypted)
    print(f"[*] Decrypted sample:\n{decrypted_text[:120]}...", flush=True)

    # Search for flag pattern (academy{...} or picoCTF{...})
    match = re.search(r"(?:academy|picoCTF)\{[^}]+\}", decrypted_text)
    if not match:
        raise ValueError(f"Flag pattern not found in decrypted text: {decrypted_text}")

    flag = match.group(0)
    print(f"[+] Flag found: {flag}", flush=True)

    flag_path = Path(__file__).parent / "flag.txt"
    flag_path.write_text(flag, encoding="utf-8")
    print(f"[+] Wrote flag to {flag_path}", flush=True)

    return flag

if __name__ == "__main__":
    solve()
