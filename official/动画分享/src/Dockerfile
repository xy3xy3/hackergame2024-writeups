# Uncomment "RUN echo"s, then do this locally for testing:
# docker build -t local/anime .
# cat <YOUR_PAYLOAD> | base64 --wrap=0 | docker run --rm --tmpfs /dev/shm:exec --tmpfs /tmp -i local/anime
FROM ustclug/debian:bullseye AS builder

RUN apt update && apt install -y git build-essential python3-dev pkg-config libfreetype-dev libxmu-dev libgles2-mesa-dev && \
    git clone https://git.hq.sig7.se/zutty.git && cd zutty && git checkout 0.12 && \
    ./waf configure && ./waf

FROM ustclug/debian:bullseye
RUN apt update && apt install -y python3 xvfb libfreetype6 libxmu6 libgles2-mesa libegl1 netcat-openbsd curl
COPY --from=builder /zutty/build/src/zutty /usr/local/bin/zutty
# Start it once to create shader cache
RUN timeout -s 9 5 xvfb-run /usr/local/bin/zutty || true
COPY src/fileserver /usr/local/bin/fileserver

# Start fileserver automatically in zutty :)
RUN echo "cd /root/chroot/ && chroot /root/chroot/ fileserver" > /root/.bashrc && \
    mkdir /root/chroot && cp -r /lib* /root/chroot/ && mkdir -p /root/chroot/usr/ /root/chroot/usr/bin/ /root/chroot/usr/local/bin/ && \
    cp -r /usr/lib* /root/chroot/usr/ && cp -r /usr/bin/* /root/chroot/usr/bin/ && cp -r /usr/local/bin/* /root/chroot/usr/local/bin/
COPY src/ /src/

# Note that you cannot just "cat /flag1" directly on server :)
# RUN echo "Submit your program to get real flag1 on server!" > /flag1 && \
#     echo "Submit your program to get real flag2 on server!" > /flag2

CMD ["python3", "-u", "/src/server.py"]
