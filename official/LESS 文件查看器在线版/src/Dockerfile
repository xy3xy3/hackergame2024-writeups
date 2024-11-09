FROM ubuntu:24.04
RUN apt update && apt upgrade -y && apt install -y less python3-pip
RUN pip3 install --break-system-packages pexpect
COPY server.py /
CMD ["/usr/bin/python3", "-u", "/server.py"]
