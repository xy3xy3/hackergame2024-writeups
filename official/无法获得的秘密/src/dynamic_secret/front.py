import base64
import OpenSSL
import os
import time
import fcntl
import signal
import tempfile
import hashlib
import atexit
import subprocess
from datetime import datetime
import threading
import select
import sys

tmp_path = "/dev/shm/hackergame"
tmp_flag_path = "/dev/shm"
conn_interval = int(os.environ["hackergame_conn_interval"])
token_timeout = int(os.environ["hackergame_token_timeout"])
challenge_timeout = int(os.environ["hackergame_challenge_timeout"])
pids_limit = int(os.environ["hackergame_pids_limit"])
mem_limit = os.environ["hackergame_mem_limit"]
secret_path = os.environ["hackergame_secret_path"]
challenge_docker_name = os.environ["hackergame_challenge_docker_name"]
read_only = 0 if os.environ.get("hackergame_read_only") == "0" else 1

# challenge_network sets whether the challenge container can access other networks. Default = no access
challenge_network = os.environ.get("hackergame_challenge_network", "")
# shm_exec sets /dev/shm no longer be noexec. Default = keep noexec
shm_exec = 1 if os.environ.get("hackergame_shm_exec") == "1" else 0
# tmp_tmpfs sets whether to explicitly mount /tmp as tmpfs. Default = no
tmp_tmpfs = 1 if os.environ.get("hackergame_tmp_tmpfs") == "1" else 0
# extra_flag directly appends to "docker create ..."
extra_flag = os.environ.get("hackergame_extra_flag", "")

secret_key = os.environ["hackergame_secret_key"]
secret_size = int(os.environ["hackergame_secret_size"])

with open("cert.pem") as f:
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, f.read())


class Secret:
    def __init__(self, flag):
        self.flag = flag


def validate(token):
    try:
        id, sig = token.split(":", 1)
        sig = base64.b64decode(sig, validate=True)
        OpenSSL.crypto.verify(cert, sig, id.encode(), "sha256")
        return id
    except Exception:
        return None


def try_login(id):
    os.makedirs(tmp_path, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(tmp_path, id), os.O_CREAT | os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX)
    with os.fdopen(fd, "r+") as f:
        data = f.read()
        now = int(time.time())
        if data:
            last_login, balance = data.split()
            last_login = int(last_login)
            balance = int(balance)
            last_login_str = (
                datetime.fromtimestamp(last_login).isoformat().replace("T", " ")
            )
            balance += now - last_login
            if balance > conn_interval * 3:
                balance = conn_interval * 3
        else:
            balance = conn_interval * 3
        if conn_interval > balance:
            print(
                f"Player connection rate limit exceeded, please try again after {conn_interval-balance} seconds. "
                f"连接过于频繁，超出服务器限制，请等待 {conn_interval-balance} 秒后重试。"
            )
            return False
        balance -= conn_interval
        f.seek(0)
        f.truncate()
        f.write(str(now) + " " + str(balance))
        return True


def check_token():
    signal.alarm(token_timeout)
    print("Please input your token: ")
    with os.fdopen(sys.stdin.fileno(), 'rb', buffering=0, closefd=False) as unbuffered_stdin:
        token = unbuffered_stdin.readline().decode().strip()
    id = validate(token)
    if not id:
        print("Invalid token")
        exit(-1)
    if not try_login(id):
        exit(-1)
    signal.alarm(0)
    return token, id

def write_secret_file(f, token):
    image = secret_key.strip().encode() + b'\0' + token.encode()
    image2 = hashlib.sha256(image).digest()
    seed = hashlib.sha256(image2).digest()
    shake256 = hashlib.shake_256(seed)
    f.write(shake256.digest(secret_size))



def generate_secret_file(token):
    with tempfile.NamedTemporaryFile("wb", delete=False, dir=tmp_flag_path) as f:
        write_secret_file(f, token)
        fn = f.name
        os.chmod(fn, 0o444)
    return fn


def cleanup():
    if child_docker_id:
        subprocess.run(
            f"docker rm -f {child_docker_id}",
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    try:
        os.unlink(secret_file_path)
    except FileNotFoundError:
        pass


def check_docker_image_exists(docker_image_name):
    return subprocess.run(
        f"docker inspect --type=image {docker_image_name}",
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    ).returncode == 0


def create_docker(secret_file_path, id):
    network = "none"
    if challenge_network:
        network = challenge_network.split()[0]
    cmd = (
        f"docker create --init --rm -i --network {network} "
        f"--pids-limit {pids_limit} -m {mem_limit} --memory-swap {mem_limit} --cpus 1 "
        f"-e hackergame_token=$hackergame_token "
    )

    if read_only:
        cmd += "--read-only "
    if shm_exec:
        cmd += "--tmpfs /dev/shm:exec "
    if tmp_tmpfs:
        cmd += "--tmpfs /tmp "
    if extra_flag:
        cmd += extra_flag + " "

    # new version docker-compose uses "-" instead of "_" in the image name, so we try both
    challenge_docker_name_checked = challenge_docker_name
    if challenge_docker_name.endswith("_challenge"):
        name_prefix = challenge_docker_name[:-10]
        if not check_docker_image_exists(challenge_docker_name):
            challenge_docker_name_checked = name_prefix + "-challenge"
    elif challenge_docker_name.endswith("-challenge"):
        name_prefix = challenge_docker_name[:-10]
        if not check_docker_image_exists(challenge_docker_name):
            challenge_docker_name_checked = name_prefix + "_challenge"
    else:
        name_prefix = challenge_docker_name

    if not check_docker_image_exists(challenge_docker_name_checked):
        print("Docker image does not exist, please contact admin")
        exit(-1)

    timestr = datetime.now().strftime("%m%d_%H%M%S_%f")[:-3]
    child_docker_name = f"{name_prefix}_u{id}_{timestr}"
    cmd += f'--name "{child_docker_name}" '

    with open("/etc/hostname") as f:
        hostname = f.read().strip()
    with open("/proc/self/mountinfo") as f:
        for part in f.read().split('/'):
            if len(part) == 64 and part.startswith(hostname):
                docker_id = part
                break
        else:
            raise ValueError('Docker ID not found')
    prefix = f"/var/lib/docker/containers/{docker_id}/mounts/shm/"


    secret_src_path = prefix + secret_file_path.split("/")[-1]
    cmd += f"-v {secret_src_path}:{secret_path}:ro "

    cmd += challenge_docker_name_checked

    return subprocess.check_output(cmd, shell=True).decode().strip()


def run_docker(child_docker_id):
    # timeout command sends SIGKILL to docker-cli, and the container would be stopped
    # in cleanup(). Please note that this command SHALL NOT BE RUN WITH Debian's dash!
    # Otherwise, when client (player) & server's buffers are all full, dash would be
    # BLOCKED when writing "Killed", and this would hang for a very long time!

    subprocess.run([
        "timeout", "-s", "9", str(challenge_timeout), "docker", "start", "-i", child_docker_id
    ])


def clean_on_socket_close():
    p = select.poll()
    p.register(sys.stdin, select.POLLHUP | select.POLLERR | select.POLLRDHUP)
    p.poll()
    cleanup()


if __name__ == "__main__":
    child_docker_id = None
    atexit.register(cleanup)
    t = threading.Thread(target=clean_on_socket_close, daemon=True)
    t.start()

    token, id = check_token()
    os.environ["hackergame_token"] = token
    secret_file_path = generate_secret_file(token)
    child_docker_id = create_docker(secret_file_path, id)
    run_docker(child_docker_id)
