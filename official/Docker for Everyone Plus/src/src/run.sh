#!/bin/bash

set -eu

IMAGE="${1}"

exec qemu-system-x86_64 \
	-kernel ./vmlinuz-virt -initrd ./initramfs-virt \
	-device virtio-blk,drive=alpine \
	-blockdev "driver=qcow2,file.filename=${IMAGE},file.driver=file,node-name=alpine,read-only=true,auto-read-only=true,cache.direct=on" \
	-append "root=UUID=47a6765a-021c-47f0-830b-de4d8bb9d727 ro modules=ext4 quiet rootfstype=ext4 oops=panic panic=1 console=ttyS0" \
	-m 256m \
	-device virtio-blk,drive=flag \
	-blockdev driver=raw,file.filename=/flag,file.driver=file,node-name=flag,read-only=true,auto-read-only=true \
	-no-reboot -monitor /dev/null -nic none -nographic \
