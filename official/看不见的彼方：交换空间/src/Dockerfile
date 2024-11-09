# Uncomment "RUN echo"s, then do this locally for testing:
# docker build -t local/swap .
# Subchallenge 1:
# { echo -n '1@'; paste -d@ <(base64 --wrap=0 <ALICEFILE>) <(base64 --wrap=0 <BOBFILE>); } | docker run --rm -m 316m --memory-swap 316m --tmpfs /dev/shm:exec --tmpfs /home/pwn/A/space/:exec --tmpfs /home/pwn/B/space/:exec -i local/swap
# Subchallenge 2:
# { echo -n '2@'; paste -d@ <(base64 --wrap=0 <ALICEFILE>) <(base64 --wrap=0 <BOBFILE>); } | docker run --rm -m 316m --memory-swap 316m --tmpfs /dev/shm:exec --tmpfs /home/pwn/A/space/:exec --tmpfs /home/pwn/B/space/:exec -i local/swap
FROM ustclug/debian:bookworm-slim

# deps
RUN apt update && apt -y upgrade && \
    apt install --no-install-recommends -y python3 busybox && \
    rm -rf /var/lib/apt/lists/*

# user
RUN useradd -m pwn && mkdir /home/pwn/A && mkdir /home/pwn/B && \
    cp -r /lib* /home/pwn/A/ && cp -r /lib* /home/pwn/B/ && \
    mkdir /home/pwn/A/usr && mkdir /home/pwn/B/usr && \
    cp -r /usr/lib* /home/pwn/A/usr/ && cp -r /usr/lib* /home/pwn/B/usr/ && \
    mkdir /home/pwn/A/bin && mkdir /home/pwn/B/bin && \
    cp /bin/python3 /bin/busybox /bin/bash /bin/sh /bin/cat /bin/ls /home/pwn/A/bin && \
    cp /bin/python3 /bin/busybox /bin/bash /bin/sh /bin/cat /bin/ls /home/pwn/B/bin && \
    mkdir /home/pwn/A/etc && mkdir /home/pwn/B/etc && \
    cp /etc/passwd /etc/group /home/pwn/A/etc/ && cp /etc/passwd /etc/group /home/pwn/B/etc/ && \
    chmod -R 555 /home/pwn

COPY server.py /

# RUN echo "Submit your program to get real flag1 on server!" > /flag1 && \
#     echo "Submit your program to get real flag2 on server!" > /flag2

CMD ["python3", "-u", "/server.py"]
