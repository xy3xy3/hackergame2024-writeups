#!/bin/bash

# . /etc/os-release
# if [ "$NAME" != "Debian GNU/Linux" ] || [ "$VERSION_ID" != "12" ]; then
#     echo "This script requires Debian 12"
# fi

echo "Note: this script requires privileged Docker container, and host with ZFS kernel module"
docker build -t local/zfs-user .
docker run -it --rm -v /dev:/dev --privileged -v $(realpath $(pwd)/..):/workspace \
  local/zfs-user /workspace/gen/run.sh
