FROM ustclug/debian:bookworm

ARG PASSWORD=YaFLxjwrXVkuUMKqZ2Lt
RUN apt update && apt -y upgrade && \
    apt install --no-install-recommends -y qemu-system wget p7zip-full ca-certificates

ADD src /src
WORKDIR /src

RUN \
 	wget "https://ftp.lug.ustc.edu.cn/~rtxux/1a62f0e6-98da-4dd6-8f8e-978bbc02ad08/2024-004.7z" && \
 	7z x "-p${PASSWORD}" 2024-004.7z && \
 	echo "cd81f0a3ab2b137017390028f0b852533785809a9516a01a3d95500bde461b92 alpine.qcow2" | sha256sum -c && \
	echo "71048b2825bfd67cf436d8df4557daa462ecc1c38fa6e1e16fbf966fcd0c6ccf alpine_2.qcow2" | sha256sum -c && \
 	rm 2024-004.7z

CMD ["/src/run.sh", "./alpine.qcow2"]
