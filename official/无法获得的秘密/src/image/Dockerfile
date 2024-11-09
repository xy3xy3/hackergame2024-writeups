FROM debian:bookworm

ENV LANG=en_US.UTF-8 \
    LC_ALL=en_US.UTF-8 \
    S6_BEHAVIOUR_IF_STAGE2_FAILS=2 \
    VNC_GEOMETRY=1024x768 \
    VNC_COLOR_DEPTH=24 \
    DEBUG=false

# Use USTC Mirrors and Update
RUN sed -i 's/deb.debian.org/mirrors.ustc.edu.cn/g' /etc/apt/sources.list.d/debian.sources && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get clean -y

# tools
RUN apt-get install -y util-linux vim wget curl net-tools locales bzip2 procps apt-utils ttf-wqy-zenhei xz-utils socat && \
    apt-get clean -y && \
    echo "${LANG} UTF-8" > /etc/locale.gen && \
    locale-gen

# TigerVNC
RUN apt-get install -y tigervnc-standalone-server && \
    apt-get clean -y

# Xfce
RUN apt-get install -y xfce4 xfce4-terminal xterm dbus-x11 libdbus-glib-1-2 && \
    apt-get purge -y pm-utils *screensaver*  && \
    apt-get clean -y

# Dev Tools
RUN apt-get install -y build-essential python3 python3-pip python3-dev python3-setuptools firefox-esr && \
    apt-get clean -y

# Add user
RUN useradd -s /bin/bash user

# Add files
ADD root-files /

ENTRYPOINT ["/usr/bin/entrypoint.sh"]
CMD ["start"]