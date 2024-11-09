# riscv64-elf-as -march=rv32i -mabi=ilp32 *.S -o a.out && riscv64-elf-objcopy -O binary a.out a.bin && python3 makehex.py a.bin > firmware.hex
# 因为指令只能读取一次，无法向前跳转，可以在寄存器中手动排序
.section .text
.macro cmpswap xa, xb
	blt \xa, \xb, .+0x10
	xor \xa, \xa, \xb
	xor \xb, \xa, \xb
	xor \xa, \xa, \xb
.endm

_start:
	la x17, 0xf80 # location of numbers
	lw x1, 0(x17)
	lw x2, 4(x17)
	lw x3, 8(x17)
	lw x4, 12(x17)
	lw x5, 16(x17)
	lw x6, 20(x17)
	lw x7, 24(x17)
	lw x8, 28(x17)
	lw x9, 32(x17)
	lw x10, 36(x17)
	lw x11, 40(x17)
	lw x12, 44(x17)
	lw x13, 48(x17)
	lw x14, 52(x17)
	lw x15, 56(x17)
	lw x16, 60(x17)
	# selection sort x1-x16 in regs
	cmpswap x1, x2
	cmpswap x1, x3
	cmpswap x1, x4
	cmpswap x1, x5
	cmpswap x1, x6
	cmpswap x1, x7
	cmpswap x1, x8
	cmpswap x1, x9
	cmpswap x1, x10
	cmpswap x1, x11
	cmpswap x1, x12
	cmpswap x1, x13
	cmpswap x1, x14
	cmpswap x1, x15
	cmpswap x1, x16

	cmpswap x2, x3
	cmpswap x2, x4
	cmpswap x2, x5
	cmpswap x2, x6
	cmpswap x2, x7
	cmpswap x2, x8
	cmpswap x2, x9
	cmpswap x2, x10
	cmpswap x2, x11
	cmpswap x2, x12
	cmpswap x2, x13
	cmpswap x2, x14
	cmpswap x2, x15
	cmpswap x2, x16

	cmpswap x3, x4
	cmpswap x3, x5
	cmpswap x3, x6
	cmpswap x3, x7
	cmpswap x3, x8
	cmpswap x3, x9
	cmpswap x3, x10
	cmpswap x3, x11
	cmpswap x3, x12
	cmpswap x3, x13
	cmpswap x3, x14
	cmpswap x3, x15
	cmpswap x3, x16

	cmpswap x4, x5
	cmpswap x4, x6
	cmpswap x4, x7
	cmpswap x4, x8
	cmpswap x4, x9
	cmpswap x4, x10
	cmpswap x4, x11
	cmpswap x4, x12
	cmpswap x4, x13
	cmpswap x4, x14
	cmpswap x4, x15
	cmpswap x4, x16

	cmpswap x5, x6
	cmpswap x5, x7
	cmpswap x5, x8
	cmpswap x5, x9
	cmpswap x5, x10
	cmpswap x5, x11
	cmpswap x5, x12
	cmpswap x5, x13
	cmpswap x5, x14
	cmpswap x5, x15
	cmpswap x5, x16

	cmpswap x6, x7
	cmpswap x6, x8
	cmpswap x6, x9
	cmpswap x6, x10
	cmpswap x6, x11
	cmpswap x6, x12
	cmpswap x6, x13
	cmpswap x6, x14
	cmpswap x6, x15
	cmpswap x6, x16

	cmpswap x7, x8
	cmpswap x7, x9
	cmpswap x7, x10
	cmpswap x7, x11
	cmpswap x7, x12
	cmpswap x7, x13
	cmpswap x7, x14
	cmpswap x7, x15
	cmpswap x7, x16

	cmpswap x8, x9
	cmpswap x8, x10
	cmpswap x8, x11
	cmpswap x8, x12
	cmpswap x8, x13
	cmpswap x8, x14
	cmpswap x8, x15
	cmpswap x8, x16

	cmpswap x9, x10
	cmpswap x9, x11
	cmpswap x9, x12
	cmpswap x9, x13
	cmpswap x9, x14
	cmpswap x9, x15
	cmpswap x9, x16

	cmpswap x10, x11
	cmpswap x10, x12
	cmpswap x10, x13
	cmpswap x10, x14
	cmpswap x10, x15
	cmpswap x10, x16

	cmpswap x11, x12
	cmpswap x11, x13
	cmpswap x11, x14
	cmpswap x11, x15
	cmpswap x11, x16

	cmpswap x12, x13
	cmpswap x12, x14
	cmpswap x12, x15
	cmpswap x12, x16

	cmpswap x13, x14
	cmpswap x13, x15
	cmpswap x13, x16

	cmpswap x14, x15
	cmpswap x14, x16

	cmpswap x15, x16

	la x17, 0xfc0 # destination of numbers
	sw x1, 0(x17)
	sw x2, 4(x17)
	sw x3, 8(x17)
	sw x4, 12(x17)
	sw x5, 16(x17)
	sw x6, 20(x17)
	sw x7, 24(x17)
	sw x8, 28(x17)
	sw x9, 32(x17)
	sw x10, 36(x17)
	sw x11, 40(x17)
	sw x12, 44(x17)
	sw x13, 48(x17)
	sw x14, 52(x17)
	sw x15, 56(x17)
	sw x16, 60(x17)

_end:
	j _end
	# trap here but don't care
