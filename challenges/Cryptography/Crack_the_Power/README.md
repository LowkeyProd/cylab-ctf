# Crack the Power

- **Category:** Cryptography
- **Difficulty:** Medium
- **Points:** 200
- **Instance Required:** No
- **Connection:** `N/A`

## Description
We received an encrypted message. The modulus is built from primes large enough that factoring them isn’t an option, at least not today. See if you can make sense of the numbers and reveal the flag.
Download the <a href='https://challenge-files.cylabacademy.net/library/c85258d1bfc43eacb36ad1dad1f13f53e3bb9de78790da47f98669733ded9001/message.txt' download>message</a>.

## Hints
- When certain values in the encryption setup are smaller than usual, it opens up unexpected shortcuts to recover the plaintext
- Consider whether you can invert the encryption without factoring `n`.
- Read more about Coppersmith's_attack [ here](https://en.wikipedia.org/wiki/Coppersmith's_attack )

## Files
- [message.txt](message.txt)
