from os import chmod, path
import subprocess
import base64
import concurrent.futures
import gc

TIMEOUT = 10


def check_file_as_regular(filename: str) -> bool:
    return path.isfile(filename)


def get_file_sha256_from_subprocess(filename: str, allow_failure: bool = False) -> str:
    try:
        p = subprocess.run(
            ["sha256sum", filename],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        if allow_failure:
            return "（获取失败）"
        else:
            raise e
    hash = p.stdout.split(b" ")[0]
    assert len(hash) == 64
    return hash.decode()


def run_command(cmd: list[str]):
    try:
        p = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=TIMEOUT,
        )
        return p
    except subprocess.TimeoutExpired as e:
        return e


if __name__ == "__main__":
    binary = input("Base64 of binary: ")
    option, file1, file2 = binary.split("@", 2)
    if option not in ["1", "2"]:
        print("Incorrect option!")
        exit(1)
    with open("/flag" + option) as f:
        flag = f.read().strip()
    with open("/home/pwn/A/space/exe", "wb") as f:
        f.write(base64.b64decode(file1))
    with open("/home/pwn/B/space/exe", "wb") as f:
        f.write(base64.b64decode(file2))
    del binary
    del file1
    del file2
    gc.collect()
    chmod("/home/pwn/A/space/exe", 0o555)
    chmod("/home/pwn/B/space/exe", 0o555)
    print("Program file writing complete.")

    if option == "1":
        # Init large files, use external programs to avoid extra RAM
        subprocess.run(
            ["dd", "if=/dev/urandom", "of=/home/pwn/A/space/file", "bs=4M", "count=32"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        subprocess.run(
            ["dd", "if=/dev/urandom", "of=/home/pwn/B/space/file", "bs=4M", "count=32"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        chmod("/home/pwn/A/space/file", 0o666)
        chmod("/home/pwn/B/space/file", 0o666)
        hash0 = get_file_sha256_from_subprocess("/home/pwn/A/space/file")
        hash1 = get_file_sha256_from_subprocess("/home/pwn/B/space/file")
    elif option == "2":
        subprocess.run(
            ["dd", "if=/dev/urandom", "of=/home/pwn/A/space/file", "bs=4M", "count=32"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        subprocess.run(
            ["dd", "if=/dev/urandom", "of=/home/pwn/B/space/file1", "bs=4M", "count=16"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        subprocess.run(
            ["dd", "if=/dev/urandom", "of=/home/pwn/B/space/file2", "bs=4M", "count=16"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        chmod("/home/pwn/A/space/file", 0o666)
        chmod("/home/pwn/B/space/file1", 0o666)
        chmod("/home/pwn/B/space/file2", 0o666)
        hash0 = get_file_sha256_from_subprocess("/home/pwn/A/space/file")
        hash1 = get_file_sha256_from_subprocess("/home/pwn/B/space/file1")
        hash2 = get_file_sha256_from_subprocess("/home/pwn/B/space/file2")
    else:
        assert 0

    print("Running Alice & Bob...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(run_command, ["chroot", "--userspec=pwn:pwn", "/home/pwn/A/", "./space/exe"])
        f2 = executor.submit(run_command, ["chroot", "--userspec=pwn:pwn", "/home/pwn/B/", "./space/exe"])

        p1 = f1.result()
        p2 = f2.result()

    print("Checking...")

    if option == "1":
        assert check_file_as_regular("/home/pwn/A/space/file"), "/home/pwn/A/space/file 不是普通文件"
        assert check_file_as_regular("/home/pwn/B/space/file"), "/home/pwn/B/space/file 不是普通文件"
        hash0_new = get_file_sha256_from_subprocess("/home/pwn/B/space/file", allow_failure=True)
        hash1_new = get_file_sha256_from_subprocess("/home/pwn/A/space/file", allow_failure=True)
        if hash0_new == hash0 and hash1_new == hash1:
            print("交换成功，你的 flag:", flag)
        else:
            print("交换失败。")
            print(f"/home/pwn/A/space/file 预期 hash: {hash1}，实际 hash: {hash1_new}")
            print(f"/home/pwn/B/space/file 预期 hash: {hash0}，实际 hash: {hash0_new}")
    elif option == "2":
        assert check_file_as_regular("/home/pwn/A/space/file1"), "/home/pwn/A/space/file1 不是普通文件"
        assert check_file_as_regular("/home/pwn/A/space/file2"), "/home/pwn/A/space/file2 不是普通文件"
        assert check_file_as_regular("/home/pwn/B/space/file"), "/home/pwn/B/space/file 不是普通文件"
        hash0_new = get_file_sha256_from_subprocess("/home/pwn/B/space/file", allow_failure=True)
        hash1_new = get_file_sha256_from_subprocess("/home/pwn/A/space/file1", allow_failure=True)
        hash2_new = get_file_sha256_from_subprocess("/home/pwn/A/space/file2", allow_failure=True)
        if hash0_new == hash0 and hash1_new == hash1 and hash2_new == hash2:
            print("交换成功，你的 flag:", flag)
        else:
            print("交换失败。")
            print(f"/home/pwn/A/space/file1 预期 hash: {hash1}，实际 hash: {hash1_new}")
            print(f"/home/pwn/A/space/file2 预期 hash: {hash2}，实际 hash: {hash2_new}")
            print(f"/home/pwn/B/space/file 预期 hash: {hash0}，实际 hash: {hash0_new}")
    else:
        assert 0
    stdout_p1 = p1.stdout[:8192].decode() if p1.stdout else ""
    stderr_p1 = p1.stderr[:8192].decode() if p1.stderr else ""
    stdout_p2 = p2.stdout[:8192].decode() if p2.stdout else ""
    stderr_p2 = p2.stderr[:8192].decode() if p2.stderr else ""
    print("Alice's stdout (标准输出，前 8192 个字节):")
    print(stdout_p1)
    print("Alice's stderr (标准错误，前 8192 个字节):")
    print(stderr_p1)
    print("Bob's stdout (标准输出，前 8192 个字节):")
    print(stdout_p2)
    print("Bob's stderr (标准错误，前 8192 个字节):")
    print(stderr_p2)
