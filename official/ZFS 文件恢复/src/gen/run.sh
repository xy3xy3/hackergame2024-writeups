#!/bin/bash

cd /workspace && ./make.sh && mkdir -p /workspace/files && rm -f /workspace/files/zfs.img* && \
   cp /tmp/zfs.img* /workspace/files/ && cd /workspace/files && zip -r zfs.zip zfs.img
