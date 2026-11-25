"""
Lightweight pwn package stub for Windows CTF automation.
Re-exports core primitives from pwn_compat.
"""
from pwn_compat import (
    remote,
    p32,
    p64,
    u32,
    u64,
    xor,
    cyclic,
    cyclic_find,
    context,
    log,
    process
)

__all__ = [
    "remote",
    "p32",
    "p64",
    "u32",
    "u64",
    "xor",
    "cyclic",
    "cyclic_find",
    "context",
    "log",
    "process"
]
