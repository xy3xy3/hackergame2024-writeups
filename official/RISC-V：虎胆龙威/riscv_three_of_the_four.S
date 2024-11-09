# riscv64-elf-as -march=rv32i -mabi=ilp32 *.S -o a.out && riscv64-elf-objcopy -O binary a.out a.bin && python3 makehex.py a.bin > firmware.hex
# rs1 只能是 x1，rs2 只能是 x16
# 几乎所有的立即数 [3:0] 都无法设置为非 0 值
# 唯一可能的访存：lw x1, 0(x1)    lw x16, 0(x1)
# addi 也只可以是 addi x1, x1, num   addi x16, x1, num
# S 和 B 型指令的立即数可以正常使用
# 但 sw 只能使用 x16 的值写入
# 如果手动排序，多半内存会不够
# 可以通过 jr 等设置并跳转到其他寄存器，但似乎很困难
.section .text

_start:
	# first, easy moving 0th, 4th, 8th, cth numbers
	la x1, 0xf80 # 2 instrs
	lw x16, (x1)
	la x1, 0xe80 # 2 instrs
	sw x16, (x1)
	la x1, 0xf90 # 2 instrs
	lw x16, (x1)
	la x1, 0xec0 # 2 instrs
	sw x16, (x1)
	la x1, 0xfa0 # 2 instrs
	lw x16, (x1)
	la x1, 0xf00 # 2 instrs
	sw x16, (x1)
	la x1, 0xfb0 # 2 instrs
	lw x16, (x1)
	la x1, 0xf40 # 2 instrs
	sw x16, (x1)
	# use auipc to create chances for unaligned
	# this will make the 4 erased to 0: la x1, 0xf84 
	# 4 and c aligned
	# 0x60
	nop
	auipc x1, 0x1 # 0x1064
	addi x1, x1, -0x80 - 0x60
	lw x16, (x1)
	la x1, 0xe90
	sw x16, (x1)
	# 0x7c
	auipc x1, 0x1 # 0x107c
	addi x1, x1, -0x80 - 0x70
	lw x16, (x1)
	la x1, 0xeb0
	sw x16, (x1)
	# 0x94
	auipc x1, 0x1
	addi x1, x1, -0x70 - 0x90
	lw x16, (x1)
	la x1, 0xed0
	sw x16, (x1)
	# 0xac
	auipc x1, 0x1
	addi x1, x1, -0x70 - 0xa0
	lw x16, (x1)
	la x1, 0xef0
	sw x16, (x1)
	# 0xc4
	auipc x1, 0x1
	addi x1, x1, -0x60 - 0xc0
	lw x16, (x1)
	la x1, 0xf10
	sw x16, (x1)
	# 0xdc
	auipc x1, 0x1
	addi x1, x1, -0x60 - 0xd0
	lw x16, (x1)
	la x1, 0xf30
	sw x16, (x1)
	# 0xf4
	auipc x1, 0x1
	addi x1, x1, -0x50 - 0xf0
	lw x16, (x1)
	la x1, 0xf50
	sw x16, (x1)
	# 0x10c
	auipc x1, 0x1
	addi x1, x1, -0x50 - 0x100
	lw x16, (x1)
	la x1, 0xf70
	sw x16, (x1)
	nop
	# 8-aligned
	# 0x128
	auipc x1, 0x1
	addi x1, x1, -0x80 - 0x120
	lw x16, (x1)
	la x1, 0xea0
	sw x16, (x1)
	nop
	nop
	# 0x148
	auipc x1, 0x1
	addi x1, x1, -0x70 - 0x140
	lw x16, (x1)
	la x1, 0xee0
	sw x16, (x1)
	nop
	nop
	# 0x168
	auipc x1, 0x1
	addi x1, x1, -0x60 - 0x160
	lw x16, (x1)
	la x1, 0xf20
	sw x16, (x1)
	nop
	nop
	# 0x188
	auipc x1, 0x1
	addi x1, x1, -0x50 - 0x180
	lw x16, (x1)
	la x1, 0xf60
	sw x16, (x1)

	# sort with accessible memory cells
	# i = 0
	sw x0, (x0) # i: 0x0, override instructions but don't care
_loop1:
	# minindex = i
	lw x16, (x0)
	sw x16, 0x20(x0) # minindex: 0x20

	# j = i + 1
	lw x1, (x0)
	addi x16, x1, 0x10
	sw x16, 0x10(x0) # j: 0x10
_loop2:
	lw x1, 0x10(x0) # j
	addi x1, x1, 0x700
	addi x1, x1, 0x780
	lw x16, (x1) # [j]
	lw x1, 0x20(x0) # minindex
	addi x1, x1, 0x700
	addi x1, x1, 0x780
	lw x1, (x1) # [minindex]
	blt x1, x16, _nosetmin
	# if [j] < [minindex]
	lw x16, 0x10(x0) # minindex = j
	sw x16, 0x20(x0)
_nosetmin:
	# j++
	lw x1, 0x10(x0)
	addi x16, x1, 0x10
	sw x16, 0x10(x0)
	lw x1, 0x10(x0)
	li x16, 0x10 * (16)
	# j < 16
	bne x1, x16, _loop2
	# swap [i] and [minindex]

	lw x1, 0x0(x0) # i
	addi x1, x1, 0x700
	addi x1, x1, 0x780
	lw x16, (x1) # [i]
	sw x16, 0x30(x0) # temp

	lw x1, 0x20(x0) # minindex
	addi x1, x1, 0x700
	addi x1, x1, 0x780
	lw x16, (x1) # [minindex]
	lw x1, 0x0(x0)
	addi x1, x1, 0x700
	addi x1, x1, 0x780
	sw x16, 0x0(x1) # i

	lw x1, 0x30(x0) # temp
	addi x16, x1, 0
	lw x1, 0x20(x0) # minindex
	addi x1, x1, 0x700
	addi x1, x1, 0x780
	sw x16, (x1) # minindex

	# i++
	lw x1, (x0)
	addi x16, x1, 0x10
	sw x16, (x0)
	lw x1, (x0)
	li x16, 0x10 * (16 - 1)
	# i < 16 - 1
	bne x1, x16, _loop1

	# copy sorted to destination
	la x1, 0xe80
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 0(x1)
	la x1, 0xe90
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 4(x1)
	la x1, 0xea0
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 8(x1)
	la x1, 0xeb0
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 12(x1)
	la x1, 0xec0
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 16(x1)
	la x1, 0xed0
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 20(x1)
	la x1, 0xee0
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 24(x1)
	la x1, 0xef0
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 28(x1)
	la x1, 0xf00
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 32(x1)
	la x1, 0xf10
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 36(x1)
	la x1, 0xf20
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 40(x1)
	la x1, 0xf30
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 44(x1)
	la x1, 0xf40
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 48(x1)
	la x1, 0xf50
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 52(x1)
	la x1, 0xf60
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 56(x1)
	la x1, 0xf70
	lw x16, (x1)
	la x1, 0xfc0
	sw x16, 60(x1)

#	nop
#	#0x10
#	nop
#	auipc x1, 0
#	addi x1, x1, 0x780
#	addi x1, x1, 0x700
#	#0x20
#	#la x1, 0xf84
#	lw x1, 0x100(x1)
#	bge x1, x16, _noswap # [0] < [1]
#	# swap [0] and [1]
#	# backup [1] to mem
#	auipc x1, 0
##	addi x1, x1, 
#	#0x30
#	la x1, 0xf84
#	lw x16, 0(x1)
#	la x1, 0xf70
#	sw x16, 0(x1)
#	# [0] to [1]
#	la x1, 0xf80
#	lw x16, 0(x1)
#	la x1, 0xf84
#	sw x16, 0(x1)
#	# mem to [0]
#	la x1, 0xf70
#	lw x16, 0(x1)
#	la x1, 0xf80
#	sw x16, 0(x1)
#	
#_noswap:
#
#
#	la x1, 0xf80
#	lw x16, 0(x1)
#	la x1, 0xfc0
#	sw x16, 0(x1)
#	la x1, 0xf84
#	lw x16, 0(x1)
#	la x1, 0xfc4
#	sw x16, 0(x1)
#	la x1, 0xf88
#	lw x16, 0(x1)
#	la x1, 0xfc8
#	sw x16, 0(x1)

_end:
	j _end
	# trap here but don't care
