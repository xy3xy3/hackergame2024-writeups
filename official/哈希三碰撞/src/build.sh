#!/bin/bash
set -ex
docker build -t hashcol3_build .
docker run --name hashcol3_build_1 hashcol3_build
docker cp hashcol3_build_1:1 ../1
docker cp hashcol3_build_1:2 ../2
docker rm hashcol3_build_1
