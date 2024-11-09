import json
import decimal
import hashlib
import sys
from cryptos import deserialize, serialize # pip install cryptos

def sha256(s):
    return hashlib.sha256(s).digest()

def doublesha(s):
    return sha256(sha256(s))

btcdata = []
with open('btc.txt') as f:
    for line in f:
        btcdata.append(line.strip().split())

bchdata = []
with open('bch.txt') as f:
    for line in f:
        bchdata.append(line.strip().split())

init = sha256(bytes.fromhex(btcdata[0][2]))
print(init.hex())
base = sha256(init)

for i in range(50):
    print(bytes.fromhex(btcdata[i + 1][2])[:4].hex())
    print(bytes.fromhex(btcdata[i + 1][2])[4+32:].hex())
    print(bytes.fromhex(bchdata[i + 1][2])[:4].hex())
    print(bytes.fromhex(bchdata[i + 1][2])[4+32:].hex())
    print()
    print()
    print()
    print()

print('Loading data', file=sys.stderr)
blockdata = []
with open('btcblock.jsonl') as f:
    for line in f:
        blockdata.append(json.loads(line, parse_float=decimal.Decimal))
with open('btcblockheader.txt') as f:
    for i, line in enumerate(f):
        blockdata[i]['headerhex'] = line.strip().split()[-1]
        assert doublesha(bytes.fromhex(blockdata[i]['headerhex'])) == bytes.fromhex(blockdata[i]['hash'])[::-1]

class DAG:
    def __init__(self):
        self.graph = {}
        self.preimages = {}

    def add_node(self, node, preimage):
        assert isinstance(node, bytes) and len(node) == 32
        assert hashlib.sha256(preimage).digest() == node
        if node not in self.graph:
            self.graph[node] = set()
            self.preimages[node] = preimage

    def add_edge(self, from_node, to_node):
        assert isinstance(from_node, bytes) and len(from_node) == 32
        assert isinstance(to_node, bytes) and len(to_node) == 32
        assert from_node in self.graph
        assert to_node in self.graph
        assert from_node in self.preimages[to_node]
        self.graph[from_node].add(to_node)

    def add_doublesha(self, from_node_preimage, to_node_preimage):
        assert isinstance(from_node_preimage, bytes)
        assert isinstance(to_node_preimage, bytes)
        from_node = doublesha(from_node_preimage)
        assert from_node in to_node_preimage
        mid_node = hashlib.sha256(to_node_preimage).digest()
        to_node = hashlib.sha256(mid_node).digest()
        self.add_node(from_node, sha256(from_node_preimage))
        self.add_node(mid_node, to_node_preimage)
        self.add_node(to_node, mid_node)
        self.add_edge(from_node, mid_node)
        self.add_edge(mid_node, to_node)
        return from_node, to_node

g = DAG()

# headers
print('Headers...', file=sys.stderr)
for b1, b2 in zip(blockdata[:-1], blockdata[1:]):
    g.add_doublesha(bytes.fromhex(b1['headerhex']), bytes.fromhex(b2['headerhex']))

# merkle trees
print('Merkle trees...', file=sys.stderr)
preimages = {}
for b in blockdata:
    for tx in b['tx']:
        s = serialize(deserialize(bytes.fromhex(tx['hex'])), include_witness=False)
        assert doublesha(s) == bytes.fromhex(tx['txid'])[::-1]
        preimages[bytes.fromhex(tx['txid'])[::-1]] = s

def calc_merkle_root(hs):
    if len(hs) == 1:
        return hs[0]
    new_hs = []
    for i in range(0, len(hs), 2):
        if i + 1 < len(hs):
            h = hs[i] + hs[i + 1]
            g.add_doublesha(preimages[hs[i]], h)
            g.add_doublesha(preimages[hs[i + 1]], h)
        else:
            h = hs[i] + hs[i]
            g.add_doublesha(preimages[hs[i]], h)
        new_hs.append(doublesha(h))
        preimages[doublesha(h)] = h
    return calc_merkle_root(new_hs)

for b in blockdata:
    merkle_root = bytes.fromhex(b['merkleroot'])[::-1]
    assert calc_merkle_root([bytes.fromhex(tx['txid'])[::-1] for tx in b['tx']]) == merkle_root
    g.add_doublesha(preimages[merkle_root], bytes.fromhex(b['headerhex']))

# utxos
print('UTXOs...', file=sys.stderr)
for b in blockdata:
    for tx in b['tx']:
        txid = bytes.fromhex(tx['txid'])[::-1]
        for vin in tx['vin']:
            if 'txid' in vin:
                utxo_txid = bytes.fromhex(vin['txid'])[::-1]
                if utxo_txid in preimages:
                    g.add_doublesha(preimages[utxo_txid], preimages[txid])

def find_all_paths(graph, start, end, path, all_paths):
    path = path + [start]
    if start == end:
        all_paths.append(path)
        return
    for node in graph[start]:
        find_all_paths(graph, node, end, path, all_paths)
    return all_paths

def print_paths(paths):
    max_bytes = 0
    max_path_len = 0
    for path in paths:
        if len(path) - 1 > max_path_len:
            max_path_len = len(path) - 1
        print(len(path) - 1)
        for from_node, to_node in zip(path[:-1], path[1:]):
            preimage = g.preimages[to_node]
            assert from_node in preimage
            index = preimage.index(from_node)
            if len(preimage[:index]) > max_bytes:
                max_bytes = len(preimage[:index])
            if len(preimage[index + len(from_node):]) > max_bytes:
                max_bytes = len(preimage[index + len(from_node):])
            print(preimage[:index].hex())
            print(preimage[index + len(from_node):].hex())
    print('Max bytes:', max_bytes, file=sys.stderr)
    print('Max path length:', max_path_len, file=sys.stderr)

def filter_paths_sizes(paths, max_bytes, max_path_len):
    filtered = []
    for path in paths:
        if len(path) - 1 > max_path_len:
            continue
        for from_node, to_node in zip(path[:-1], path[1:]):
            preimage = g.preimages[to_node]
            if len(preimage) > max_bytes + len(from_node):
                break
            assert from_node in preimage
            index = preimage.index(from_node)
            if index > max_bytes:
                break
            if len(preimage) - index - len(from_node) > max_bytes:
                break
        else:
            filtered.append(path)
    return filtered

for b in blockdata[::-1]:
    for i, tx in enumerate(b['tx']):
        s = serialize(deserialize(bytes.fromhex(tx['hex'])), include_witness=False)
        start = doublesha(s)
        paths = find_all_paths(g.graph, start, base, [], [])
        print(b['height'], i, len(paths), file=sys.stderr)
        if len(paths) >= 100:
            filtered = filter_paths_sizes(paths, 1000, 100)
            if len(filtered) >= 100:
                print(g.preimages[start].hex())
                print_paths(filtered[:100])
                exit()
