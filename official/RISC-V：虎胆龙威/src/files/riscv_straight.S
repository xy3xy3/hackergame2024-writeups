# riscv64-elf-as -march=rv32i -mabi=ilp32 *.S -o a.out && riscv64-elf-objcopy -O binary a.out a.bin && python3 makehex.py a.bin > firmware.hex
.section .text
_start:
	la a0, 0xf80 # location of numbers
	la a1, 0xfc0 # location to write sorted numbers
	li t0, 0 # i
	li t2, 15*4 # n-1
_loop1:
	li t1, 0 # j
	sub t3, t2, t0 # n-1-i
_loop2:
	add t4, a0, t1
	lw s0, (t4) # [j]
	lw s1, 4(t4) # [j+1]
	bltu s0, s1, _noexchange
	mv s2, s0
	mv s0, s1
	mv s1, s2
	sw s0, (t4)
	sw s1, 4(t4)
_noexchange:
	addi t1, t1, 4 # j++
	bne t1, t3, _loop2
	addi t0, t0, 4 # i++
	bne t0, t2, _loop1

	li t0, 0 # copy to destination
	li t2, 16*4
_loop3:
	add t4, a0, t0
	add t5, a1, t0
	lw s0, (t4)
	sw s0, (t5)
	addi t0, t0, 4
	bne t0, t2, _loop3

_end:
	j _end
