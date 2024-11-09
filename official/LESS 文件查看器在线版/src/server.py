import base64
import os
import sys
import pexpect
import time
import re

if __name__ == "__main__":
    print("Files:")
    os.makedirs('/dev/temp', exist_ok=True)
    while True:
        filename = sys.stdin.readline()
        if filename == '#EOF\n':
            break
        content = sys.stdin.readline()
        filename = base64.b64decode(filename).decode().split('/')[-1]
        with open(f"/dev/temp/{filename}", "wb") as f:
            f.write(base64.b64decode(content))
        banner = '-' * 80 + '\n' + filename + '\n' + '-' * 80

        os.environ['FN'] = filename
        os.environ['TERM'] = 'xterm-256color'

        p = pexpect.spawn('/bin/bash', cwd='/dev/temp', echo=False)
        p.expect('/dev/temp#')
        p.sendline('less -N -- "$FN"')
        time.sleep(1)
        data = p.read_nonblocking(1048576, 0.1)
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])|\x1B=')
        print(banner)
        print(ansi_escape.sub('', data.decode()).strip('\r\n'))
