#!/usr/bin/env python3

import subprocess
import base64
import os
import time
import socket


def health_check() -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)

        sock.connect(("127.0.0.1", 8000))

        request = f"GET / HTTP/1.1\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode("utf-8"))

        sock.recv(8192)

        sock.close()

        return True

    except Exception as e:
        # print(f"Error: {e}")
        return False


def init_env() -> None:
    p = subprocess.Popen(
        [
            "/src/init.sh",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd="/dev/shm/",
    )

    for i in range(5):
        if health_check():
            return
        time.sleep(1)

    raise RuntimeError("init.sh starts failed!")


if __name__ == "__main__":
    binary = input("Base64 of binary: ")
    with open("/dev/shm/executable", "wb") as f:
        f.write(base64.b64decode(binary))
    with open("/flag1") as f:
        flag1 = f.read()
    os.chmod("/dev/shm/executable", 0o555)
    init_env()
    try:
        output = subprocess.run(
            [
                "/dev/shm/executable",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            user="nobody",
            group="nogroup",
            timeout=10
        )
    except subprocess.TimeoutExpired as e:
        output = e
        output.returncode = "(timeout)"
    if not health_check():
        print("Oops! The fileserver is not alive!")
        print(flag1)
    stdout = output.stdout[:8192].decode() if output.stdout else ""
    stderr = output.stderr[:8192].decode() if output.stderr else ""
    print("Return code:", output.returncode)
    print("stdout (标准输出，前 8192 个字节):")
    print(stdout)
    print("stderr (标准错误，前 8192 个字节):")
    print(stderr)
