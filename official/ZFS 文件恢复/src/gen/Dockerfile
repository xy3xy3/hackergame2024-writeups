FROM ustclug/debian:bookworm

RUN sed -i "s/main/main contrib/" /etc/apt/sources.list.d/debian.sources && \
    apt update && apt install --no-install-recommends -y zfsutils-linux jq zip
