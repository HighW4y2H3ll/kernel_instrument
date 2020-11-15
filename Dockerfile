From debian:buster-slim

# Buster is the last version of Debian that supports MIPS (32bits big endian) libraries
Run dpkg --add-architecture armel

Run apt-get update && apt-get install -y \
        gcc-arm-linux-gnueabi g++-arm-linux-gnueabi

Run apt-get install -y git python3 libglib2.0-dev:armel libfdt-dev:armel libpixman-1-dev:armel
Run apt-get install -y make flex bison

# Kernel Build
Run apt-get update && apt-get install -y bc u-boot-tools libncurses-dev libssl-dev
Run apt-get install -y kmod
