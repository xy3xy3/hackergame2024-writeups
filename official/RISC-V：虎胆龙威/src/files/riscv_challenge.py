#!/usr/bin/env python3

import os
import sys
import secrets
import subprocess

if __name__ == "__main__":
    print("RISCV DIE HARD")
    print("1. Fault in the hart")
    print("2. Fragility")
    print("3. Three of the four")
    print("Choose your challenge: ")
    choice = input()
    if choice.startswith('1'):
        challenge = 'FAULT_IN_THE_HART'
    elif choice.startswith('2'):
        challenge = 'FRAGILITY'
    elif choice.startswith('3'):
        challenge = 'THREE_OF_THE_FOUR'
    else:
        exit(1)

    print("Input your firmware in hex (empty line to end): ")
    fw = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        fw.append(line)
        if len(fw) >= 1 and fw[-1] == '':
            break
        if len(fw) > 1025:
            print('No more memory for you...')
            break
    with open("/tmp/firmware.hex", "w") as fd:
        for i in fw:
            fd.write(i)
            fd.write('\n')
        fd.close()
    sys.stdout.flush()

    p = subprocess.run(["iverilog", "-D", challenge, "-o", "/tmp/testbench", "testbench.v", "picorv32.v"], cwd="/files")
    if p.returncode != 0:
        print("Unknown compilation error. ")
        print(p.stdout.decode())
        exit(1)

    for i in range(10):
        print("Round ", i)
        maxnumber = 0x10000 if challenge == 'THREE_OF_THE_FOUR' else 0x80000000
        with open("/tmp/numbers.hex", "w") as fd:
            if i == 8:
                n = secrets.randbelow(maxnumber)
                for i in range(16):
                    fd.write((f"{n:08x}\n"))
            elif i == 9:
                for i in range(8):
                    fd.write((f"{secrets.randbelow(maxnumber):08x}\n"))
                for i in range(8):
                    fd.write((f"{0:08x}\n"))
            else:
                for i in range(16):
                    fd.write((f"{secrets.randbelow(maxnumber):08x}\n"))
            fd.close()
        p = subprocess.run(["vvp", "-N", "/tmp/testbench"], cwd="/files")
        if p.returncode != 0:
            exit(1)
    if choice.startswith('1'):
        print('Fault in the hart accomplished! ')
        subprocess.run(["cat", "/flag1"])
    elif choice.startswith('2'):
        print('Fragility accomplished! ')
        subprocess.run(["cat", "/flag2"])
    elif choice.startswith('3'):
        print('Three of the four accomplished! ')
        subprocess.run(["cat", "/flag3"])

