obj-m += dump.o

all:
	make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- -C /workdir/log/linux M=$(PWD) modules

clean:
	make ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- -C /workdir/log/linux M=$(PWD) clean
