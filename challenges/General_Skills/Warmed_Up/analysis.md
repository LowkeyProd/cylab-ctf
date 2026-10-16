# Mathematical & Algorithmic Analysis: Warmed Up (#58)

## 1. Executive Summary & Problem Overview
- **Challenge Title:** Warmed Up
- **Challenge ID:** 58
- **Category:** General Skills
- **Difficulty:** Easy (1/5)
- **Target Connection:** Offline / Static (Parameters in `connection.cfg` are empty; no live instance required)
- **Problem Statement:** What is `0x3D` (base 16) in decimal (base 10)?
- **Flag Format:** `academy{<decimal_value>}`

---

## 2. Input Structure & Encoding Analysis
1. **Input Format:**
   - Prefix: `0x` denotes a hexadecimal (base 16) literal representation.
   - Digits: `3D`
     - Digit at position 1 (weight $16^1$): `'3'` $\rightarrow 3_{10}$
     - Digit at position 0 (weight $16^0$): `'D'` $\rightarrow 13_{10}$ (where hexadecimal digits map: $\text{A}=10, \text{B}=11, \text{C}=12, \text{D}=13, \text{E}=14, \text{F}=15$).
2. **Environment & Connection Context:**
   - Inspection of `connection.cfg`:
     ```cfg
     HOST=
     PORT=0
     URL=
     ```
   - No external TCP/HTTP network interaction is needed.

---

## 3. Mathematical Formulation & Number System Theory

### 3.1. Positional Numeral System
In a positional numeral system of base $b \in \mathbb{N}_{\ge 2}$, any non-negative integer $N$ represented by an ordered sequence of digits $(d_{k-1} d_{k-2} \dots d_1 d_0)_b$ with $0 \le d_i < b$ is defined by the polynomial:

$$N = \sum_{i=0}^{k-1} d_i \cdot b^i$$

### 3.2. Concrete Evaluation for $0\text{x}3\text{D}_{16}$
Here $b = 16$, $k = 2$, with:
- $d_1 = 3$
- $d_0 = 13$

Applying the expansion formula:
$$N = d_1 \cdot 16^1 + d_0 \cdot 16^0$$
$$N = 3 \cdot 16 + 13 \cdot 1$$
$$N = 48 + 13 = 61$$

### 3.3. Algorithmic Transformation: Horner's Method
Alternatively, evaluating the number base conversion algorithmically can be modeled using Horner's rule for polynomial evaluation:
$$N = (\dots ((d_{k-1} \cdot b + d_{k-2}) \cdot b + d_{k-3}) \dots ) \cdot b + d_0$$

For a 2-digit sequence:
$$N = 3 \times 16 + 13 = 61$$

---

## 4. Complexity & Constraints Analysis
- **Time Complexity:** $\mathcal{O}(L)$ where $L$ is the number of digits. Here $L = 2$, giving deterministic $\mathcal{O}(1)$ runtime.
- **Space Complexity:** $\mathcal{O}(1)$ auxiliary memory.
- **Precision Limits:** Well within standard 32-bit/64-bit integer ranges, preventing arithmetic overflow.

---

## 5. Verification & Deterministic Solution
In Python:
```python
hex_str = "0x3D"
decimal_val = int(hex_str, 16)
assert decimal_val == 61
flag = f"academy{{{decimal_val}}}"
```

Running [`solve.py`](file:///Users/lowkeyprod/Documents/USTH/CTF/cylab/challenges/General_Skills/Warmed_Up/solve.py) yields the exact flag:
```text
academy{61}
```
Saved to [`flag.txt`](file:///Users/lowkeyprod/Documents/USTH/CTF/cylab/challenges/General_Skills/Warmed_Up/flag.txt).
