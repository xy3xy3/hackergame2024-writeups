# fault in the hart
# bnez is the only compare-branch we have!
# 只能加法，那减法用负数实现就好了，la 就是这么做的，但立即数之外的部分还是很难处理
# 个人想到的办法：使用位运算比大小，每次比较一个 bit
.section .text
_start:
	la s0, 0xf80 # location of numbers
	la s1, 0xfc0 # location to write sorted numbers
#	cmp usage example
#	lw a0, (s0)
#	lw a1, 4(s0)
#	jal ra, _cmp
#	bnez a3, _noswap 
#	j _swap
#_swap:
#	mv a2, a0
#	mv a0, a1
#	mv a1, a2
#_noswap:
#	sw a0, (s1)
#	sw a1, 4(s1)
#
#_end:
#	j _end

	# selection sort has no minus
	li t0, 0 # i
	li t2, 15*4 # n-1
_loop1:
	mv t5, t0 # minindex = i
	addi t1, t0, 4 # j = i + 1
	li t3, 16*4 # n
_loop2:
	add t4, s0, t1 # j
	add t6, s0, t5 # minindex
	lw a0, (t4) # [j]
	lw a1, (t6) # [minindex]
	jal ra, _cmp
	bnez a3, _smaller
	j _larger
_smaller:
	mv t5, t1 # minindex = j
_larger:
	addi t1, t1, 4 # j++
	mv a0, t1
	mv a1, t3
	jal ra, _cmp
	bnez a3, _loop2
	# swap [i] and [minindex]
	add t4, s0, t0 # i
	add t6, s0, t5 # minindex
	lw a0, (t4) # [i]
	lw a1, (t6) # [minindex]
	mv a2, a0
	mv a0, a1
	mv a1, a2
	sw a0, (t4)
	sw a1, (t6)
	addi t0, t0, 4 # i++
	mv a0, t0
	mv a1, t2
	jal ra, _cmp
#	sw a1, (s0)
	bnez a3, _loop1
_endloop1:
	lw t0, 0(s0)
	sw t0, 0(s1)
	lw t0, 4(s0)
	sw t0, 4(s1)
	lw t0, 8(s0)
	sw t0, 8(s1)
	lw t0, 12(s0)
	sw t0, 12(s1)
	lw t0, 16(s0)
	sw t0, 16(s1)
	lw t0, 20(s0)
	sw t0, 20(s1)
	lw t0, 24(s0)
	sw t0, 24(s1)
	lw t0, 28(s0)
	sw t0, 28(s1)
	lw t0, 32(s0)
	sw t0, 32(s1)
	lw t0, 36(s0)
	sw t0, 36(s1)
	lw t0, 40(s0)
	sw t0, 40(s1)
	lw t0, 44(s0)
	sw t0, 44(s1)
	lw t0, 48(s0)
	sw t0, 48(s1)
	lw t0, 52(s0)
	sw t0, 52(s1)
	lw t0, 56(s0)
	sw t0, 56(s1)
	lw t0, 60(s0)
	sw t0, 60(s1)

_end:
	j _end


_cmp: # a0, a1: param, a3: return, 1 if smaller(<), 0 if larger or equal
	addi s11, x0, 1
_nextbit:
	# if s11 >= 24 (check with 32), numbers are equal
	srli s10, s11, 5
	bnez s10, _c_10 # Both beqz and benz will be bnez!
	sll s8, a0, s11 # begin from original number
	sll s9, a1, s11
	srli s8, s8, 31
	srli s9, s9, 31
	bnez s8, _c_1x
	j _c_0x
_c_0x:
	bnez s9, _c_01
	j _c_00
_c_1x:
	bnez s9, _c_11
	j _c_10
_c_11:
_c_00:
	addi s11, s11, 1
	j _nextbit

_c_10:
	addi a3, x0, 0
	jr ra
_c_01:
	addi a3, x0, 1
	jr ra
