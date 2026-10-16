#!/usr/bin/env python3
"""
Solve script for So Meta (#19)
Target: challenge-files.cylabacademy.net:443
"""
from pwn import *

HOST = "challenge-files.cylabacademy.net"
PORT = 443

def solve():
    io = remote(HOST, PORT)
    data = io.recvall(timeout=5).decode(errors="ignore")
    print(data)
    io.close()

if __name__ == "__main__":
    solve()
