#!/bin/bash

arm-linux-gnueabi-objcopy -O binary -R .comment -S  vmlinux arch/arm/boot/Image
