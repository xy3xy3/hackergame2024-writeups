# Author: tl2cents 2024.08
# Run in sage version 10.2
from sage.all import GF, PolynomialRing, pari, ZZ
import subprocess
from Crypto.Cipher import AES
import os

x = GF(2)["x"].gen()
gf2e = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)

# Converts an integer to a gf2e element, little endian.
def _to_gf2e(n):
    return gf2e([(n >> i) & 1 for i in range(127, -1, -1)])

# Converts a gf2e element to an integer, little endian.
def _from_gf2e(p):
    n = p.to_integer()
    ans = 0
    for i in range(128):
        ans <<= 1
        ans |= ((n >> i) & 1)
    return int(ans)

def gcm_multi_key_collision(keys: list[bytes], associated_data: bytes = b"", nonce: bytes = b"\x00" * 12, target_tag: bytes = b"\x00" * 16, option="NTL"):
    """ Find a valid (ciphertext, tag) pair for a given set of keys and associated data.

    Args:
        keys (list[bytes]): A list of target keys.
        ad (bytes, optional): the associated data. Defaults to b"".
    """
    assert option in ["NTL", "SAGE", "PARI"], "Error: Invalid option"
    assert len(nonce) == 12, "Error: Invalid nonce length"
    xs = []
    ys = []
    t = _to_gf2e(int.from_bytes(target_tag, byteorder="big"))
    l = len(keys)
    l1 = len(associated_data)
    l2 = l * 16
    ad = associated_data + (bytes(16 - l1 % 16) if l1 % 16 != 0 else b"")
    ad_blocks = [_to_gf2e(int.from_bytes(ad[i:i+16], byteorder="big")) for i in range(0, len(ad), 16)]
    len_block = _to_gf2e(int(((8 * l1) << 64) | (8 * l2)))
    
    for key in keys:
        cipher = AES.new(key, AES.MODE_ECB)
        hbytes = cipher.encrypt(b"\x00" * 16)
        h = _to_gf2e(int.from_bytes(hbytes, byteorder="big"))
        const_bytes = cipher.encrypt(nonce + b"\x00\x00\x00\x01")
        const_coeff = _to_gf2e(int.from_bytes(const_bytes, byteorder="big"))
        y = t - const_coeff - len_block * h + sum([ci * h ** (i + l + 2) for i, ci in enumerate(ad_blocks[::-1])])
        xs.append(h)
        ys.append(y/h**2)
    x = GF(2)["x"].gen()
    gf2e = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)
    if option == "SAGE":
        pr = PolynomialRing(gf2e, 'x')
        mpoly = pr.lagrange_polynomial(zip(xs, ys))
        mblocks = [_from_gf2e(c).to_bytes(16, byteorder="big") for c in mcoeffs]
        return b"".join(mblocks[::-1])
    elif option == "PARI":
        mpoly = pari.polinterpolate(xs, ys)
        mcoeffs = [gf2e(mpoly[i]) for i in range(l)]
        mblocks = [_from_gf2e(c).to_bytes(16, byteorder="big") for c in mcoeffs]
        return b"".join(mblocks[::-1])
    elif option == "NTL":
        mcoeffs = ntl_fast_polynomial_interpolation(xs, ys)
        mblocks = [_from_gf2e(c).to_bytes(16, byteorder="big") for c in mcoeffs]
        return b"".join(mblocks[::-1])
    
def aes_gcm_256(key: bytes, msg: bytes, ad: bytes, nonce: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(ad)
    return cipher.encrypt_and_digest(msg)

def aes_gcm_256_decrypt(key: bytes, ct: bytes, ad: bytes, nonce: bytes, tag: bytes):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(ad)
    return cipher.decrypt_and_verify(ct, tag)

def ntlhex_to_gf2e(hexstr):
    return gf2e.from_integer(int(hexstr[2:][::-1], 16))

def ntl_fast_polynomial_interpolation(xs, ys, ntl_binary = "./interpolate", input_file="input.txt", output_file="output.txt"):
    gf2e = xs[0].parent()
    modzz = ZZ(gf2e.modulus().list(),2)
    with open(input_file, "w") as f:
        f.write(f"{modzz}\n")
        for x, y in zip(xs, ys):
            f.write(f"{x.to_integer()} {y.to_integer()}\n")
    # run ntl_binary input_file output_file and check return code
    p = subprocess.run([ntl_binary, input_file, output_file])
    assert p.returncode == 0, f"Error: NTL interpolation failed, {p.stderr}"
    with open(output_file, "r") as f:
        poly = (f.readline().strip().strip("[]").split(" "))
        return [ntlhex_to_gf2e(coeff) for coeff in poly if len(coeff) > 0]

if __name__ == "__main__":
    keys = [os.urandom(32) for _ in range(2**15)]
    ad = b"Associated data"
    nonce = os.urandom(12)
    target_tag = os.urandom(16)
    import time
    st = time.time()
    ct = gcm_multi_key_collision(keys, ad, nonce, target_tag)
    print(f"Multi-Key Collision Time taken: {time.time()-st:.2f}s")
    st = time.time()
    for key in keys:
        res = aes_gcm_256_decrypt(key, ct, ad, nonce, target_tag)
    print(f"Validating Time taken: {time.time()-st:.2f}s")