FROM ubuntu:24.04
RUN apt update && apt upgrade -y && apt install -y build-essential libssl-dev
COPY 1.c /
COPY 2.c /
RUN gcc -Wall 1.c -lcrypto -o 1
RUN gcc -Wall 2.c -lcrypto -o 2
CMD ["/bin/true"]
