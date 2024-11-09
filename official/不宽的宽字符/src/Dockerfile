# FROM ustclug/debian:bookworm AS builder

# RUN apt update && apt install -y mingw-w64
# COPY wider.cpp /wider.cpp
# RUN x86_64-w64-mingw32-g++ -static wider.cpp -o wider.exe

FROM ustclug/debian:bookworm
RUN dpkg --add-architecture i386 && apt update && apt -y upgrade && \
    apt install --no-install-recommends -y wine wine64 wine32:i386 && \
    winecfg
# COPY --from=builder /wider.exe /wider.exe
COPY wider.exe /wider.exe
CMD ["wine", "/wider.exe"]
