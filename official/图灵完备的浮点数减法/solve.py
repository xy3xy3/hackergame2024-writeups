import sys
sys.setrecursionlimit(10000)

MAGIC0 = float(2 ** 52)
MAGIC1 = float(2 ** 53)

class Node:
    def __init__(self):
        pass

    def __sub__(self, o):
        if isinstance(o, float):
            o = Const(o)
        if isinstance(o, Const) and o.value == 0.0:
            return self
        if isinstance(self, Const) and isinstance(o, Const):
            return Const(self.value - o.value)
        assert isinstance(o, Node)
        return Sub(self, o)

    def __rsub__(self, o):
        if isinstance(o, float):
            o = Const(o)
        assert isinstance(o, Node)
        return o - self

    def __add__(self, o):
        if isinstance(self, Const) and self.value == 0.0:
            return o
        if isinstance(o, Const) and o.value == 0.0:
            return self
        if isinstance(o, float) and o == 0.0:
            return self
        if isinstance(o, float):
            o = Const(o)
        if isinstance(self, Const) and isinstance(o, Const):
            return Const(self.value + o.value)
        if isinstance(o, Const):
            return self - (-o.value)
        if isinstance(self, Const):
            return o - (-self.value)
        assert isinstance(o, Node)
        return self - (0.0 - o)

    def __radd__(self, o):
        return self + o

    def __invert__(self):
        if isinstance(self, Const) and self.value == 0.0:
            return Const(1.0)
        if isinstance(self, Const) and self.value == 1.0:
            return Const(0.0)
        return 1.0 - self

    def __and__(self, o):
        if isinstance(o, Const) and o.value == 0.0:
            return o
        if isinstance(self, Const) and self.value == 0.0:
            return self
        if isinstance(o, Const) and o.value == 1.0:
            return self
        if isinstance(self, Const) and self.value == 1.0:
            return o
        if isinstance(self, Const) and isinstance(o, Const):
            return Const(float(bool(self.value) and bool(o.value)))
        assert isinstance(o, Node)
        return self + o - 1.0 - MAGIC1 + MAGIC1

    def __or__(self, o):
        if isinstance(o, Const) and o.value == 0.0:
            return self
        if isinstance(self, Const) and self.value == 0.0:
            return o
        if isinstance(o, Const) and o.value == 1.0:
            return o
        if isinstance(self, Const) and self.value == 1.0:
            return self
        if isinstance(self, Const) and isinstance(o, Const):
            return Const(float(bool(self.value) or bool(o.value)))
        assert isinstance(o, Node)
        return self + o - 1.0 + MAGIC1 - (MAGIC1 - 1.0)

    def __xor__(self, o):
        if isinstance(o, Const) and o.value == 0.0:
            return self
        if isinstance(self, Const) and self.value == 0.0:
            return o
        if isinstance(o, Const) and o.value == 1.0:
            return ~self
        if isinstance(self, Const) and self.value == 1.0:
            return ~o
        if isinstance(self, Const) and isinstance(o, Const):
            return Const(float(bool(self.value) ^ bool(o.value)))
        assert isinstance(o, Node)
        return (self & ~o) | (~self & o)

    def trunc(self, i): # x // (2 ** i) * (2 ** i)
        return self - float(2 ** (i - 1) - 0.5) + (MAGIC0 + 2.0) * 2 ** i - (MAGIC0 + 2.0) * 2 ** i

    def div2(self, i): # 0 -> 0, 2 ** i -> 2 ** (i - 1)
        return self - float(2 ** (i - 1)) - MAGIC1 * 2 ** (i - 1) + MAGIC1 * 2 ** (i - 1)

    def get_bits(self):
        x = self
        bits = []
        for i in range(7, -1, -1):
            t = x.trunc(i)
            x -= t
            for j in range(i, 0, -1):
                t = t.div2(j)
            bits.append(t)
        return bits

    @classmethod
    def make_byte(cls, bits):
        byte = 0.0
        for bit in bits:
            byte += byte
            byte += bit
        return byte

    @classmethod
    def true(cls):
        return Const(1.0)

    @classmethod
    def false(cls):
        return Const(0.0)

cache = {}

class Const(Node):
    def __init__(self, value):
        super().__init__()
        self.value = float(value)
        if value in cache:
            self.id = cache[value]
        else:
            self.id = len(cache)
            cache[value] = self.id

class Sub(Node):
    def __init__(self, l, r):
        super().__init__()
        assert isinstance(l, Node)
        assert isinstance(r, Node)
        self.l = l
        self.r = r
        if (l.id, r.id) in cache:
            self.id = cache[(l.id, r.id)]
        else:
            self.id = len(cache)
            cache[(l.id, r.id)] = self.id

class InputData(Node):
    def __init__(self, index):
        super().__init__()
        self.index = index
        if ('input', index) in cache:
            self.id = cache[('input', index)]
        else:
            self.id = len(cache)
            cache[('input', index)] = self.id

class NodeBytes: # big endian
    def __init__(self, nodes):
        assert len(nodes) % 8 == 0
        assert all(isinstance(node, Node) for node in nodes)
        self.nodes = nodes

    @classmethod
    def from_input(cls, size):
        nodes = [InputData(i) for i in range(size)]
        bit_nodes = []
        for node in nodes:
            bit_nodes.extend(node.get_bits())
        return cls(bit_nodes)

    def to_output(self):
        nodes = []
        for i in range(len(self.nodes) // 8):
            nodes.append(Node.make_byte(self.nodes[i * 8: i * 8 + 8]))
        return nodes

    @classmethod
    def from_byte(cls, b):
        return cls([Const((b >> i) & 1) for i in range(8)][::-1])

    @classmethod
    def from_bytes(cls, bs):
        nodes = []
        for b in bs:
            nodes.extend([Const((b >> i) & 1) for i in range(8)][::-1])
        return cls(nodes)

    @classmethod
    def from_uint32(cls, n):
        assert isinstance(n, NoteUint32)
        assert len(n.nodes) == 32
        return cls(n.nodes[::-1])

    def __add__(self, o):
        assert isinstance(o, NodeBytes)
        return NodeBytes(self.nodes + o.nodes)

    def __getitem__(self, key):
        if isinstance(key, slice):
            assert key.step == None
            return NodeBytes(self.nodes[key.start * 8: key.stop * 8])
        raise NotImplementedError()

    def to_uint32(self):
        assert len(self.nodes) == 32
        return NoteUint32(self.nodes[::-1])

class NoteUint32: # little endian
    def __init__(self, nodes):
        assert len(nodes) == 32
        assert all(isinstance(node, Node) for node in nodes)
        self.nodes = nodes

    @classmethod
    def from_uint32(cls, n):
        assert isinstance(n, int) and n in range(2 ** 32)
        return cls([Const((n >> i) & 1) for i in range(32)])

    def __add__(self, o):
        if isinstance(o, int):
            o = NoteUint32.from_uint32(o)
        assert isinstance(o, NoteUint32)
        result = []
        carry = Node.false()
        for i in range(32):
            x = self.nodes[i]
            y = o.nodes[i]
            z = carry
            nx = ~x
            ny = ~y
            nz = ~z
            t0 = nx & ny
            t1 = x & y
            t2 = t0 | t1
            result.append(t2 & z | ~t2 & nz)
            carry = t1 | ~t0 & z
        return NoteUint32(result)

    def __radd__(self, o):
        return self + o

    def __and__(self, o):
        assert isinstance(o, NoteUint32)
        return NoteUint32([self.nodes[i] & o.nodes[i] for i in range(32)])

    def __or__(self, o):
        assert isinstance(o, NoteUint32)
        return NoteUint32([self.nodes[i] | o.nodes[i] for i in range(32)])

    def __xor__(self, o):
        assert isinstance(o, NoteUint32)
        return NoteUint32([self.nodes[i] ^ o.nodes[i] for i in range(32)])

    def __invert__(self):
        return NoteUint32([~self.nodes[i] for i in range(32)])

    def __lshift__(self, o):
        assert isinstance(o, int) and o in range(32)
        return NoteUint32([Node.false()] * o + self.nodes[:32 - o])

    def __rshift__(self, o):
        assert isinstance(o, int) and o in range(32)
        return NoteUint32(self.nodes[o:] + [Node.false()] * o)


def sha256(data):
    digest = [NoteUint32.from_uint32(x) for x in [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]]
    data = data + NodeBytes.from_bytes(b'\x80' + b'\x00' * 29 + b'\x01\x00')

    W = []

    ROR = lambda x, y: (x >> (y & 31)) | (x << (32 - (y & 31)))
    # Ch = lambda x, y, z: (z ^ (x & (y ^ z)))
    Ch = lambda x, y, z: x & y | ~x & z
    Maj = lambda x, y, z: (((x | y) & z) | (x & y))
    S = lambda x, n: ROR(x, n)
    R = lambda x, n: x >> n
    Sigma0 = lambda x: (S(x, 2) ^ S(x, 13) ^ S(x, 22))
    Sigma1 = lambda x: (S(x, 6) ^ S(x, 11) ^ S(x, 25))
    Gamma0 = lambda x: (S(x, 7) ^ S(x, 18) ^ R(x, 3))
    Gamma1 = lambda x: (S(x, 17) ^ S(x, 19) ^ R(x, 10))

    for i in range(16):
        W.append(data[4 * i : 4 * i + 4].to_uint32())

    for i in range(16, 64):
        W.append(Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16])

    def RND(a, b, c, d, e, f, g, h, i, ki):
        t0 = h + Sigma1(e) + Ch(e, f, g) + ki + W[i]
        t1 = Sigma0(a) + Maj(a, b, c)
        d += t0
        h = t0 + t1
        return d, h

    ss = digest[:]

    ss[3], ss[7] = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],0,0x428a2f98)
    ss[2], ss[6] = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],1,0x71374491)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],2,0xb5c0fbcf)
    ss[0], ss[4] = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],3,0xe9b5dba5)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],4,0x3956c25b)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],5,0x59f111f1)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],6,0x923f82a4)
    ss[4], ss[0] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],7,0xab1c5ed5)
    ss[3], ss[7] = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],8,0xd807aa98)
    ss[2], ss[6] = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],9,0x12835b01)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],10,0x243185be)
    ss[0], ss[4] = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],11,0x550c7dc3)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],12,0x72be5d74)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],13,0x80deb1fe)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],14,0x9bdc06a7)
    ss[4], ss[0] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],15,0xc19bf174)
    ss[3], ss[7] = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],16,0xe49b69c1)
    ss[2], ss[6] = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],17,0xefbe4786)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],18,0x0fc19dc6)
    ss[0], ss[4] = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],19,0x240ca1cc)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],20,0x2de92c6f)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],21,0x4a7484aa)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],22,0x5cb0a9dc)
    ss[4], ss[0] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],23,0x76f988da)
    ss[3], ss[7] = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],24,0x983e5152)
    ss[2], ss[6] = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],25,0xa831c66d)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],26,0xb00327c8)
    ss[0], ss[4] = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],27,0xbf597fc7)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],28,0xc6e00bf3)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],29,0xd5a79147)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],30,0x06ca6351)
    ss[4], ss[0] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],31,0x14292967)
    ss[3], ss[7] = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],32,0x27b70a85)
    ss[2], ss[6] = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],33,0x2e1b2138)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],34,0x4d2c6dfc)
    ss[0], ss[4] = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],35,0x53380d13)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],36,0x650a7354)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],37,0x766a0abb)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],38,0x81c2c92e)
    ss[4], ss[0] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],39,0x92722c85)
    ss[3], ss[7] = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],40,0xa2bfe8a1)
    ss[2], ss[6] = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],41,0xa81a664b)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],42,0xc24b8b70)
    ss[0], ss[4] = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],43,0xc76c51a3)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],44,0xd192e819)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],45,0xd6990624)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],46,0xf40e3585)
    ss[4], ss[0] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],47,0x106aa070)
    ss[3], ss[7] = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],48,0x19a4c116)
    ss[2], ss[6] = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],49,0x1e376c08)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],50,0x2748774c)
    ss[0], ss[4] = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],51,0x34b0bcb5)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],52,0x391c0cb3)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],53,0x4ed8aa4a)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],54,0x5b9cca4f)
    ss[4], ss[0] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],55,0x682e6ff3)
    ss[3], ss[7] = RND(ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],56,0x748f82ee)
    ss[2], ss[6] = RND(ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],57,0x78a5636f)
    ss[1], ss[5] = RND(ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],ss[5],58,0x84c87814)
    ss[0], ss[4] = RND(ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],ss[4],59,0x8cc70208)
    ss[7], ss[3] = RND(ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],ss[3],60,0x90befffa)
    ss[6], ss[2] = RND(ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],ss[2],61,0xa4506ceb)
    ss[5], ss[1] = RND(ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],ss[1],62,0xbef9a3f7)
    ss[4], ss[0] = RND(ss[1],ss[2],ss[3],ss[4],ss[5],ss[6],ss[7],ss[0],63,0xc67178f2)

    result = NodeBytes([])
    for i, x in enumerate(digest):
        result += NodeBytes.from_uint32(x + ss[i])
    return result

def generate_program(input_size, output_nodes):
    program = []
    mapping = {}
    const_mapping = {}
    next_index = input_size

    def put(node):
        nonlocal next_index
        if isinstance(node, InputData):
            return node.index
        elif isinstance(node, Const):
            if node.value in const_mapping:
                return const_mapping[node.value]
            const_mapping[node.value] = next_index
            mapping[node.id] = next_index
            next_index += 1
            program.append(node.value)
            return next_index - 1
        elif isinstance(node, Sub):
            if node.id in mapping:
                return mapping[node.id]
            l = put(node.l)
            r = put(node.r)
            mapping[node.id] = next_index
            program.append((l, r))
            next_index += 1
            return next_index - 1

    output_index = []
    for node in output_nodes:
        output_index.append(put(node))

    for index in output_index:
        program.append((index, const_mapping[0.0]))

    return program

def print_program(program):
    for i, x in enumerate(program):
        if isinstance(x, float):
            print(f'{x}')
        elif isinstance(x, tuple):
            print(f'{x[0]} {x[1]}')

if __name__ == '__main__':
    input_data = NodeBytes.from_input(32)
    result = sha256(input_data)
    program = generate_program(32, result.to_output())
    print_program(program)
    print('EOF')
