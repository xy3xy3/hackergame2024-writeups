#!/bin/sh

set -eu

FILE=/tmp/zfs.img
ZPOOL=hg2024
FLAG1="flag{p1AInNNmmnnmmntExxt_50easy~r1ght?~}"
MTIME1=233696969
ATIME1=1141919810
MTIME2=1357924680
ATIME2=2109876543

# Calculate flag2
flag_key="hg2024_${ATIME1}.${MTIME1}_${ATIME2}.${MTIME2}_zfs"
checksum="$(printf "%s" "$flag_key" | sha256sum)"
FLAG2="flag{snapshot_$(printf "%s" "$flag_key" | sha1sum | head -c 32)}"

truncate -s 0 "$FILE"
truncate -s 64M "$FILE"
losetup -f "$FILE"
DEV="$(losetup -J |
  jq -r --arg file "$FILE" '.loopdevices[] | select(."back-file" == $file) | .name')"
zpool create \
  -o ashift=9 \
  -O atime=off \
  -O compression=gzip \
  -O redundant_metadata=none \
  -O xattr=off \
  "$ZPOOL" "$DEV"

DATASET="$ZPOOL/data"
#zfs create -o recordsize=4k -o hg2024:prop="$FLAG1" "$DATASET"
zfs create -o recordsize=4k "$DATASET"

FILE1="/$DATASET/flag1.txt"
python3 -c 'import random, string; print(end="".join(random.choices(string.ascii_lowercase, k=4094)))' > "$FILE1"
echo "$FLAG1" >> "$FILE1"
touch -m -d "@$MTIME1" "$FILE1"
touch -a -d "@$ATIME1" "$FILE1"

FILE2="/$DATASET/flag2.sh"
sed "s/CHECKSUM/$checksum/" "$(dirname "$0")/flag2.sh" > "$FILE2"
chmod 755 "$FILE2"
touch -m -d "@$MTIME2" "$FILE2"
touch -a -d "@$ATIME2" "$FILE2"

exec 3< "$FILE1"
exec 4< "$FILE2"
rm "$FILE1" "$FILE2"
SNAPSHOT="$DATASET@mysnap"
zfs snapshot "$SNAPSHOT"
exec 3>&-
exec 4>&-

# Hide recordsize
zfs inherit recordsize "$DATASET"
zpool sync "$ZPOOL"
zfs send "$SNAPSHOT" > "$FILE".zfs-send
zpool export "$ZPOOL"
losetup -d "$DEV"

# Print results
echo "Flag 1: $FLAG1"
echo "Flag 2: $FLAG2"
