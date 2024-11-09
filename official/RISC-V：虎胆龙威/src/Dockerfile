FROM python:3.12
RUN apt update && apt -y upgrade && \
    apt install --no-install-recommends -y iverilog && \
    rm -rf /var/lib/apt/lists/*
ADD files /files
CMD ["/usr/local/bin/python3", "-u", "/files/riscv_challenge.py"]
