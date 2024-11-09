import requests
from base64 import b64encode, b64decode
from itertools import product
import hashlib
import os
from ghash_nonce_reuse import aes_gcm_forgery_attack

url = "your_url_here"

signup_url = url + "register"
login_url =  url + "login"
recover_url = url + "recover"
user_url = url + "users.html"

def signup(uname: bytes, password: bytes):
    data = {
        "username": b64encode(uname).decode(),
        "password": b64encode(password).decode()
    }
    res = requests.post(signup_url, json=data)
    print(f"{res = }")
    print(f"{res.text = }")
    
    if res.status_code == 200:
        return True, res.text
    print("Error: ", res.status_code)
    return False, res.status_code

def login(uname: bytes, password: bytes):
    data = {
        "username": b64encode(uname).decode(),
        "password": b64encode(password).decode()
    }
    res = requests.post(login_url, json=data)
    if res.status_code == 200:
        return True, res.text
    print("Error: ", res.status_code)
    return False, res.status_code

def recover(recovery_code: str, new_password: str, super_mode=False):
    data = {
        "recovery_code": recovery_code.strip('""'),
        "new_password": new_password,
        "super_mode": super_mode
    }
    res = requests.post(recover_url, json=data)
    if res.status_code == 200:
        return True, res.text
    print("Error: ", res.status_code)
    return False, res.status_code

def deserialize_recoverycode(recoverycode: str):
    raw_bytes = b64decode(recoverycode.encode())
    ct = []
    for _ in range(3):
        length = int.from_bytes(raw_bytes[:8], byteorder="little")
        data = raw_bytes[8:8+length]
        # print(f"{length = }")
        # print(f"{data = }")
        ct.append(data)
        raw_bytes = raw_bytes[8+length:]
    assert len(raw_bytes) == 0, "Error: Invalid recovery code"
    return ct

def serialize_recoverycode(ct: list) -> str:
    raw_bytes = b""
    for data in ct:
        raw_bytes += len(data).to_bytes(8, byteorder="little")
        raw_bytes += data
    return b64encode(raw_bytes).decode()

def generate_possible_keys(uname: bytes):
    keys = []
    pwd_space = product("012345678", repeat=6)
    for pwd in pwd_space:
        data = uname + "".join(pwd).encode()
        key = hashlib.sha256(data).digest()
        keys.append(key)
    return keys

def login_and_get_users(uname: bytes, password: bytes):
    status, res = login(uname, password)
    if status:
        response_list = eval(res)
        headers = {"Authorization": "Bearer " + response_list[0]}
        res = requests.get(user_url, headers=headers)
        if res.status_code == 200:
            return True, res.text
    return False, res.status_code

uname1 = b"tl2ents"
uname2 = b"tl2ents\x00"
password = b"password"
new_password = b"new_password"
admin_ad = b"admin=true"

status, recoverycode1 = signup(uname1, password)
_, res = login(uname1, password)


ct1, nonce1, ad1 = deserialize_recoverycode(recoverycode1)
status, recoverycode2 = signup(uname2, password)
assert status, "Error: Signup failed"
ct2, nonce2, ad2 = deserialize_recoverycode(recoverycode2)
assert nonce1 == nonce2

solutions = list(aes_gcm_forgery_attack(ad1, ct1[:-16], ct1[-16:],
                                                      ad2, ct2[:-16], ct2[-16:],
                                                      uname1, uname1, admin_ad))

print(f"{solutions = }")
for forged_ct, forged_tag in solutions:
    new_recoverycode = serialize_recoverycode([forged_ct + forged_tag, nonce1, admin_ad])
    print(f"{new_recoverycode = }")
    status, msg = recover(new_recoverycode, new_password.decode())
    if status:
        print(f"{status = }")
        print(f"{msg = }")
        _, res = login(uname1, new_password)
        print(f"{res = }")
        break