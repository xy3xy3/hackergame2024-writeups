#!/usr/bin/python3

from sys import argv

with open(argv[1], "rb") as f:
    bindata = f.read()

assert len(bindata) < 60*1024
assert len(bindata) % 4 == 0

for i in range(len(bindata)//4):
        w = bindata[4*i : 4*i+4]
        print("%02x%02x%02x%02x" % (w[3], w[2], w[1], w[0]))
