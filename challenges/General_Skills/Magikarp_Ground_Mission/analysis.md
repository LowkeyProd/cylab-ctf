# Analysis: Magikarp Ground Mission (#189)

## 1. Challenge Overview
- **Title:** Magikarp Ground Mission
- **Category:** General Skills
- **Difficulty:** Easy (1/3)
- **Target Host:** `chatelaine.cylabacademy.net`
- **Target Port:** `37440`
- **User:** `ctf-player`
- **Credential:** `f6904eaa`
- **Target Service:** SSH

## 2. Structural & Architectural Analysis
The challenge simulates a file navigation task inside a Linux shell container:
- The user is dropped into `/home/ctf-player`.
- The full flag is partitioned into 3 sequential components:
  1. Part 1: Stored at `/home/ctf-player/drop-in/1of3.flag.txt`
  2. Part 2: Stored at `/2of3.flag.txt`
  3. Part 3: Stored at `/home/ctf-player/3of3.flag.txt`

## 3. Algorithmic Transformation & Concatenation
The reconstruction of the flag token follows string concatenation:
$$\text{Flag} = \text{Part}_1 \mathbin{\Vert} \text{Part}_2 \mathbin{\Vert} \text{Part}_3$$

Extracted fragments:
- $\text{Part}_1 = \texttt{academy\{xxsh\_}$
- $\text{Part}_2 = \texttt{0ut\_0f\_//4t3r\_}$
- $\text{Part}_3 = \texttt{47c47679\}}$

$$\text{Flag} = \texttt{academy\{xxsh\_0ut\_0f\_//4t3r\_47c47679\}}$$

## 4. Automation Strategy (`solve.py`)
- Parse connection configuration dynamically from `connection.cfg`.
- Establish SSH transport connection via `paramiko`.
- Read file fragments deterministically.
- Write verified flag to `flag.txt` and print clean token to stdout.
