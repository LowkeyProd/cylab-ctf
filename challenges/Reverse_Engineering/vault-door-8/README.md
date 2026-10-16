# vault-door-8

- **Category:** Reverse Engineering
- **Difficulty:** Hard
- **Points:** 450
- **Instance Required:** No
- **Connection:** `https://challenge-files.cylabacademy.net/library/0b7c9ff3145fd1a47f09ac08c11072dd1d23d2684d24df1388d720ff47e738a2/VaultDoor8.java`

## Description
Apparently Dr. Evil's minions knew that our agency was making copies of their source code, because they intentionally sabotaged this source code in order to make it harder for our agents to analyze and crack into! The result is a quite mess, but I trust that my best special agent will find a way to solve it.
The source code for this vault is here: <a href='https://challenge-files.cylabacademy.net/library/0b7c9ff3145fd1a47f09ac08c11072dd1d23d2684d24df1388d720ff47e738a2/VaultDoor8.java' download>VaultDoor8.java</a>

## Hints
- Clean up the source code so that you can read it and understand what is going on.
- Draw a diagram to illustrate which bits are being switched in the scramble() method, then figure out a sequence of bit switches to undo it. You should be able to reuse the switchBits() method as is.

## Files
- [VaultDoor8.java](VaultDoor8.java)
