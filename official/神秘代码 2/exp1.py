from base64 import b64decode
import zlib
from string import *

data1 = b64decode(input())
data2 = list(input().strip().strip('=').encode())

alpha = data1[-64:]
calpha = ascii_uppercase + ascii_lowercase + digits + "+/"
calpha = calpha.encode()
print(alpha, calpha)
for i in range(len(data2)):
  data2[i] = calpha[alpha.index(data2[i])]

data2 = bytes(data2) + b"=" * (-len(data2)%4)

print(data2)

print(zlib.decompress(b64decode(data2)))
