obj-m += singlefilefs.o
singlefilefs-objs += singlefilefs_src.o file.o dir.o

all:
	gcc singlefilemakefs.c -o singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

load-FS-driver:
	sudo insmod singlefilefs.ko

unload-FS-driver:
	sudo rmmod singlefilefs

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm singlefilemakefs
	rmdir /tmp/refmon_log
	rm image

create-fs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image
	mkdir /tmp/refmon_log
	
mount-fs:
	sudo mount -o loop -t singlefilefs image /tmp/refmon_log/

unmount-fs:
	sudo umount /tmp/refmon_log/
