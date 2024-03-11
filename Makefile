obj-m += the_reference-monitor.o
the_reference-monitor-objs += reference-monitor.o lib/scth.o

all:
	make -C /lib/modules/$$(uname -r)/build M=$(PWD)/usctm modules 
	make -C /lib/modules/$$(uname -r)/build M=$(PWD) modules 
clean:
	make -C /lib/modules/$$(uname -r)/build M=$(PWD)/usctm clean
	make -C /lib/modules/$$(uname -r)/build M=$(PWD) clean
mount:
	cd usctm && insmod the_usctm.ko
	insmod the_reference-monitor.ko the_syscall_table=$$(cat /sys/module/the_usctm/parameters/sys_call_table_address)
unmount:
	cd usctm && rmmod the_usctm.ko
	rmmod the_reference-monitor.ko

enable_rec_on:
	echo "1" > /sys/module/the_reference-monitor/parameters/enable_rec_on 
enable_rec_off:
	echo "1" > /sys/module/the_reference-monitor/parameters/enable_rec_off 

disable_rec_on:
	echo "0" > /sys/module/the_queuing_service/parameters/enable_rec_on 
disable_rec_off:
	echo "0" > /sys/module/the_queuing_service/parameters/enable_rec_off 
	
# check:
# 	cat /sys/module/the_queuing_service/parameters/count

