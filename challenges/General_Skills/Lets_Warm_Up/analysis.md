# Analysis - Lets Warm Up (#22)

## 1. Problem Specification & Input Format
- **Challenge Title:** Lets Warm Up
- **Category:** General Skills (Difficulty: Easy / 1)
- **Target Connection:** Static (No active network service required; `connection.cfg` has empty host/port).
- **Given Value:** Hexadecimal integer `0x70`
- **Question:** What does a word starting with `0x70` start with in ASCII?
- **Flag Pattern:** `academy{...}` (per challenge hints)

## 2. Mathematical & Algorithmic Formulation

### 2.1 Radix Conversion (Hexadecimal to Decimal)
A positional numeral system with base $b = 16$ defines the value of integer $\text{0x}d_1 d_0$:
$$N = \sum_{i=0}^{n} d_i \cdot 16^i$$
For $d_1 = 7$ and $d_0 = 0$:
$$N = 7 \cdot 16^1 + 0 \cdot 16^0 = 112_{10}$$

### 2.2 Character Encoding Mapping (ASCII Standard)
The American Standard Code for Information Interchange (ASCII) maps integers in the range $[0, 127]$ to typographic and control symbols:
$$\text{ASCII}: [0, 127] \to \Sigma$$
For value $112_{10}$:
$$\text{char}(112) = \text{'p'}$$

Verification:
- Binary: $112_{10} = 01110000_2$
- Hexadecimal: $0111_2 = 7_{16}$, $0000_2 = 0_{16} \implies \text{0x70}$
- ASCII character: Lowercase Latin letter `'p'`

## 3. Flag Synthesis
Applying the target platform container template:
$$\text{Flag} = \text{academy} \Vert \{\text{chr}(0\text{x}70)\} = \text{academy\{p\}}$$

## 4. Implementation Specification (`solve.py`)
- Programmatically check/parse `connection.cfg`.
- Convert `0x70` to ASCII character `'p'`.
- Format as `academy{p}`.
- Persist token to `flag.txt`.
- Print clean token `academy{p}` to standard output.
