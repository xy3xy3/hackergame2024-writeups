import requests
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from itertools import product
import hashlib
import time
from ghash_multi_collision import gcm_multi_key_collision

url = "your_url_here"
uname = b"the_admin_username_from_users_page"

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
    

keys = generate_possible_keys(uname)
nonce = b"\x00" * 12
tag = b"\x00" * 16
ad = b"admin=true"

print(f"{len(keys) = }")
kset_size = 2**15
key_sets = [keys[i:i + kset_size] for i in range(0, len(keys), kset_size)]
key_sets = key_sets[:-2] + [key_sets[-2].extend(key_sets[-1])]
for key_set in key_sets:
    st = time.time()
    ct = gcm_multi_key_collision(key_set, ad, nonce, tag)
    print(f"Collision Time: {time.time() - st}")
    recover_code = serialize_recoverycode([ct + tag, nonce, ad])
    status, msg = recover(recover_code, "123456", True)
    print(f"Round time: {time.time() - st}")
    if msg == 404:    
        # decrypted successfully
        print(f"Key Space Reduced to {len(key_set)}")
        break

# key_set = key_sets[1]
while len(key_set)!= 1:
    lsize = len(key_set)
    tmp_set = key_set[:lsize//2]
    ct = gcm_multi_key_collision(tmp_set, ad, nonce, tag)
    recover_code = serialize_recoverycode([ct + tag, nonce, ad])
    status, msg = recover(recover_code, "123456", True)
    if msg == 404:    
        # decrypted successfully
        key_set = tmp_set
    else:
        key_set = key_set[lsize//2:]
    print(f"Key Space Reduced to {lsize//2}")
    
print(f"Final Key: {key_set[0].hex()}")

# reset password of admin
key = key_set[0]
nonce = b"\x00" * 12
ad = b"admin=true"
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
cipher.update(ad)
ct, tag = cipher.encrypt_and_digest(uname)
rcode = serialize_recoverycode([ct + tag, nonce, ad])
status, msg = recover(rcode, "admin", True)
print(f"{status = }, {msg = }")
status, flag = login(uname, b"admin")
print(f"{status = }, {flag = }")