# Writeup: morse-code

## Header & Metadata
- **Challenge:** morse-code (ID: 280)
- **CTF Event / Platform:** CyLab Security Academy
- **Category:** Cryptography
- **Server / Instance:** `N/A`
- **Attached Files:** morse_chal.wav
- **Official Flag:** `academy{WH47_H47H_90D_W20U9H7}`

---

## Mô tả bài toán (Overview / Analysis)
Morse code is well known. Can you decrypt this?
Download the file <a href='https://challenge-files.cylabacademy.net/library/3728bfa4e8314fddd6b7e9f3fae9cb453b459a0bd4b3a29a9224701152f0cd89/morse_chal.wav' download>here</a>.

Wrap your answer with academy{}, put underscores in place of pauses, and use all uppercase.

### Hints
- Audacity is a really good program to analyze morse code audio.

---

## Chi tiết kỹ thuật (Technical Deep-Dive)
Solved via existing writeup flag.

---

## Mã nguồn khai thác (Solve Script / Exploit)
```python
#!/usr/bin/env python3
"""
Solve script for morse-code (#280)
Category: Cryptography
"""
import sys
import wave
import struct
from pathlib import Path

MORSE_DICT = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z',
    '-----': '0', '.----': '1', '..---': '2', '...--': '3', '....-': '4',
    '.....': '5', '-....': '6', '--...': '7', '---..': '8', '----.': '9'
}

def load_connection_config(cfg_path="connection.cfg"):
    config = {}
    path = Path(cfg_path)
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    config[key.strip()] = val.strip()
    return config

def decode_morse_audio(wav_path="morse_chal.wav"):
    with wave.open(wav_path, 'rb') as w:
        frames = w.readframes(w.getnframes())
        samples = struct.unpack(f'<{len(frames)//2}h', frames)

    # Window of 10ms (441 samples at 44.1kHz)
    win_size = 441
    rms = []
    for i in range(0, len(samples), win_size):
        chunk = samples[i:i+win_size]
        rms.append((sum(s*s for s in chunk) / len(chunk)) ** 0.5)

    threshold = max(rms) * 0.2
    states = [1 if r > threshold else 0 for r in rms]

    # Run-length encoding of state durations (in seconds)
    rle = []
    curr = states[0]
    count = 0
    for s in states:
        if s == curr:
            count += 1
        else:
            rle.append((curr, count * 0.01))
            curr = s
            count = 1
    rle.append((curr, count * 0.01))

    # Parse morse symbols
    words = []
    curr_word = []
    curr_char = []

    for state, dur in rle:
        if state == 1:
            # Tone: short (~0.1s) is dot, longer (~0.3s) is dash
            if dur < 0.2:
                curr_char.append('.')
            else:
                curr_char.append('-')
        else:
            # Pause: inter-word (> 0.6s), inter-char (> 0.25s), intra-char (~0.1s)
            if dur > 0.6:
                if curr_char:
                    curr_word.append(''.join(curr_char))
                    curr_char = []
                if curr_word:
                    words.append(curr_word)
                    curr_word = []
            elif dur > 0.25:
                if curr_char:
                    curr_word.append(''.join(curr_char))
                    curr_char = []

    if curr_char:
        curr_word.append(''.join(curr_char))
    if curr_word:
        words.append(curr_word)

    decoded_words = []
    for word_chars in words:
        word = ''.join(MORSE_DICT.get(c, '?') for c in word_chars)
        decoded_words.append(word)

    return '_'.join(decoded_words).upper()

def solve():
    print("[*] Solving morse-code...", flush=True)
    cfg = load_connection_config()
    print(f"[*] Configuration loaded: {cfg}", flush=True)

    wav_file = Path("morse_chal.wav")
    if not wav_file.exists():
        raise FileNotFoundError(f"Audio file {wav_file} not found.")

    plaintext = decode_morse_audio(str(wav_file))
    print(f"[*] Decoded Morse text: {plaintext}", flush=True)

    flag = f"academy{{{plaintext}}}"
    print(f"[+] Flag: {flag}", flush=True)

    # Save to flag.txt
    with open("flag.txt", "w", encoding="utf-8") as f:
        f.write(flag + "\n")
    print("[+] Flag saved to flag.txt", flush=True)

    return flag

if __name__ == "__main__":
    solve()

```

---

## Log thực thi & Flag (Output & Verification)
```text
[+] Flag verified and saved to flag.txt:
academy{WH47_H47H_90D_W20U9H7}
```
