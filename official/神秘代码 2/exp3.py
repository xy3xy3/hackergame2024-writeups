import base64
import zlib
import itertools

data2 = input().strip()

# 代码最后是搞你心态的

alpha = "abcdefghijklmnop"
data2 = [ ord(i) - ord('a') for i in data2]
print(data2)
sane = list(range(3, 7))

def checkposs(l):
  global data2
  exc = [list(range(16)) for _ in range(l)]
  ptr = 0
  for i, c in enumerate(data2):
    if i % 2 == 0:
      nex = []
      for x in exc[ptr]:
        if (data2[i] - x) % 16 in sane:
          nex.append(x)
      exc[ptr] = nex
    ptr = (ptr + 1) % l
  return exc

def decoder(state):
  tar = [''] * 24
  cnt = 0
  ptr = 0
  while True:
    tar[ptr] = state[cnt]
    cnt = (cnt * 0x0d + 7) % 24
    ptr = ptr + 1
    if cnt == 0:
      break
  return [int(''.join(tar[7::-1]), 2), int(''.join(tar[15:7:-1]), 2), int(''.join(tar[23:15:-1]), 2)]

for i in range(5, 7):
  c = checkposs(i * 2 + 1)
  for pw in itertools.product(*c):
    dd = [(i - u) % 16 for i, u in zip(data2, pw*100)]
    vv = ""
    for i in range(0, len(dd), 2):
      vv = vv + bin(dd[i] - 3)[2:].zfill(2) + bin(dd[i + 1])[2:].zfill(4)
    xx = []
    for i in range(0, len(vv), 24):
      xx = xx + decoder(vv[i:i+24])
    print(xx)
    try:
      print(zlib.decompress(bytes(xx)))
    except:
      pass
