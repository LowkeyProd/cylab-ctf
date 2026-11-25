# SideChannel

- **Category:** Forensics
- **Difficulty:** Hard
- **Points:** 400
- **Instance Required:** Yes
- **Connection:** `N/A`

## Description
There's something fishy about this PIN-code checker, can you figure out the PIN and get the flag?

Download the PIN checker program here <a href='https://challenge-files.cylabacademy.net/library/616ad6e80d5e2bb925a2618b1baf907751cd39cb0966e716a78505d98a4771b0/pin_checker' download>pin_checker</a>

## Hints
- Read about "timing-based side-channel attacks."
- Attempting to reverse-engineer or exploit the binary won't help you, you can figure out the PIN just by interacting with it and measuring certain properties about it.
- Don't run your attacks against the master server, it is secured against them. The PIN code you get from the `pin_checker` binary is the same as the one for the master server.

## Files
- [pin_checker](pin_checker)
