"""
Lightweight pwn compatibility module (pwn_compat) for Windows / environments without full pwntools.
Provides drop-in replacements for:
- remote(host, port, ...)
- p32, p64, u32, u64
- xor, cyclic, cyclic_find
- context, log
"""
import sys
import socket
import struct
import time
from typing import Union, Optional

class Context:
    log_level = "info"
    arch = "amd64"
    bits = 64
    endian = "little"
    terminal = ["cmd.exe"]

context = Context()

class Log:
    @staticmethod
    def info(msg: str):
        if context.log_level != "error":
            print(f"[*] {msg}")

    @staticmethod
    def success(msg: str):
        print(f"[+] {msg}")

    @staticmethod
    def warn(msg: str):
        print(f"[!] {msg}")

    @staticmethod
    def error(msg: str):
        print(f"[-] {msg}")

log = Log()

def p32(val: int, endian: str = "little", sign: bool = False) -> bytes:
    fmt = ("<" if endian == "little" else ">") + ("i" if sign else "I")
    return struct.pack(fmt, val & 0xFFFFFFFF)

def p64(val: int, endian: str = "little", sign: bool = False) -> bytes:
    fmt = ("<" if endian == "little" else ">") + ("q" if sign else "Q")
    return struct.pack(fmt, val & 0xFFFFFFFFFFFFFFFF)

def u32(data: bytes, endian: str = "little", sign: bool = False) -> int:
    if isinstance(data, str):
        data = data.encode("latin-1")
    data = data.ljust(4, b"\x00")[:4]
    fmt = ("<" if endian == "little" else ">") + ("i" if sign else "I")
    return struct.unpack(fmt, data)[0]

def u64(data: bytes, endian: str = "little", sign: bool = False) -> int:
    if isinstance(data, str):
        data = data.encode("latin-1")
    data = data.ljust(8, b"\x00")[:8]
    fmt = ("<" if endian == "little" else ">") + ("q" if sign else "Q")
    return struct.unpack(fmt, data)[0]

def xor(*args) -> bytes:
    if not args:
        return b""
    items = []
    for a in args:
        if isinstance(a, str):
            items.append(a.encode("latin-1"))
        elif isinstance(a, (int, bytes, bytearray)):
            if isinstance(a, int):
                items.append(bytes([a]))
            else:
                items.append(bytes(a))
    res = bytearray(items[0])
    for item in items[1:]:
        for i in range(len(res)):
            res[i] ^= item[i % len(item)]
    return bytes(res)

def cyclic(length: int = 128) -> bytes:
    """Generate simple cyclic pattern (de Bruijn style) for buffer overflow offset discovery."""
    chars = b"abcdefghijklmnopqrstuvwxyz"
    pattern = bytearray()
    for a in chars:
        for b in chars:
            for c in chars:
                for d in chars:
                    pattern.extend([a, b, c, d])
                    if len(pattern) >= length:
                        return bytes(pattern[:length])
    return bytes(pattern[:length])

def cyclic_find(sub: Union[bytes, str, int]) -> int:
    """Find offset in cyclic pattern."""
    if isinstance(sub, int):
        sub = p32(sub)
    elif isinstance(sub, str):
        sub = sub.encode("latin-1")
    full = cyclic(4096)
    idx = full.find(sub)
    return idx

class remote:
    def __init__(self, host: str, port: int, timeout: int = 15):
        self.host = host
        self.port = int(port)
        self.timeout = timeout
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.sock.settimeout(self.timeout)
        self.buffer = bytearray()
        log.info(f"Connected to {self.host}:{self.port}")

    def send(self, data: Union[bytes, str]):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.sock.sendall(data)

    def sendline(self, data: Union[bytes, str] = b""):
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.send(data + b"\n")

    def recv(self, numb: int = 4096, timeout: Optional[int] = None) -> bytes:
        if timeout:
            self.sock.settimeout(timeout)
        try:
            chunk = self.sock.recv(numb)
            if timeout:
                self.sock.settimeout(self.timeout)
            return chunk
        except Exception:
            return b""

    def recvline(self, timeout: Optional[int] = None) -> bytes:
        return self.recvuntil(b"\n", timeout=timeout)

    def recvuntil(self, delim: Union[bytes, str], timeout: Optional[int] = None) -> bytes:
        if isinstance(delim, str):
            delim = delim.encode("utf-8")
        if timeout:
            self.sock.settimeout(timeout)
        t_start = time.time()
        while delim not in self.buffer:
            try:
                chunk = self.sock.recv(1024)
                if not chunk:
                    break
                self.buffer.extend(chunk)
            except Exception:
                break
            if timeout and (time.time() - t_start > timeout):
                break
        if timeout:
            self.sock.settimeout(self.timeout)

        idx = self.buffer.find(delim)
        if idx != -1:
            end = idx + len(delim)
            result = bytes(self.buffer[:end])
            del self.buffer[:end]
            return result
        result = bytes(self.buffer)
        self.buffer.clear()
        return result

    def recvall(self, timeout: int = 5) -> bytes:
        self.sock.settimeout(timeout)
        while True:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                self.buffer.extend(chunk)
            except Exception:
                break
        self.sock.settimeout(self.timeout)
        result = bytes(self.buffer)
        self.buffer.clear()
        return result

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

# Alias for compatibility
process = None
