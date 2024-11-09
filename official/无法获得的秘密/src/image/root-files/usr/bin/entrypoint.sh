#!/bin/bash

set -euo pipefail

case ${1} in
    start)
        # prepare user home
        export DISPLAY=:0
        export HOME=/home/root

        install -d -o root -g root -m 0700 "${HOME}"

        install -d -o user -g user -m 0700 ~user
        install -o user -g user -m 0600 -t ~user /etc/skel/.*

        # start vncserver as user
        mkdir -p /run/vnc

        /bin/sh -l -e <<EOF > /dev/null 2>&1 &
cd "${HOME}"
exec /usr/bin/vncserver :0 -desktop "user@vnc" -fg -geometry "${VNC_GEOMETRY}" -depth "${VNC_COLOR_DEPTH}" -rfbport -1 -rfbunixpath /run/vnc/vncserver.sock -SecurityTypes None --I-KNOW-THIS-IS-INSECURE -xstartup /etc/vnc/xstartup
EOF

        while [[ ! -S /run/vnc/vncserver.sock ]]; do
            sleep 1
        done

        chown root: -R /run/vnc
        chmod 0700 /run/vnc
        # connect socket to stdio
        exec socat UNIX-CONNECT:/run/vnc/vncserver.sock STDIO
        ;;
    *)
        exec "$@"
        ;;
esac
