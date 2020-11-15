#!/bin/bash

./patch.py vmlinux test
./run.sh arm-linux-gnueabi-objcopy -O binary -R .comment -S workdir/test workdir/testImg
