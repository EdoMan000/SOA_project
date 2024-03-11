obj-m += the_reference-monitor.o
the_reference-monitor-objs += reference-monitor.o lib/scth.o

all:
	@make -C /lib/modules/$$(uname -r)/build M=$(PWD)/usctm modules 
	@make -C /lib/modules/$$(uname -r)/build M=$(PWD) modules 
clean:
	@make -C /lib/modules/$$(uname -r)/build M=$(PWD)/usctm clean
	@make -C /lib/modules/$$(uname -r)/build M=$(PWD) clean
mount:
	@cd usctm && sudo insmod the_usctm.ko
	@sudo insmod the_reference-monitor.ko the_syscall_table=$$(sudo cat /sys/module/the_usctm/parameters/sys_call_table_address)
unmount:
	@cd usctm && sudo rmmod the_usctm.ko
	@sudo rmmod the_reference-monitor.ko

enable_rec_on:
	@sudo bash -c 'echo "1" > /sys/module/the_reference_monitor/parameters/enable_rec_on'
	@echo "The reference monitor can now be reconfigured in ON mode"
enable_rec_off:
	@sudo bash -c 'echo "1" > /sys/module/the_reference_monitor/parameters/enable_rec_off'
	@echo "The reference monitor can now be reconfigured in OFF mode"
	@echo ""

disable_rec_on:
	@sudo bash -c 'echo "0" > /sys/module/the_reference_monitor/parameters/enable_rec_on'
	@echo "The reference monitor can no longer be reconfigured in ON mode"
disable_rec_off:
	@sudo bash -c 'echo "0" > /sys/module/the_reference_monitor/parameters/enable_rec_off'
	@echo "The reference monitor can no longer be reconfigured in OFF mode"
	
check_rec:
	@sudo bash -c 'rec_on="$$(cat /sys/module/the_reference_monitor/parameters/enable_rec_on 2>/dev/null)"; \
              rec_off="$$(cat /sys/module/the_reference_monitor/parameters/enable_rec_off 2>/dev/null)"; \
              if [ "$$rec_on" -eq 1 ] && [ "$$rec_off" -eq 1 ]; then \
                  echo "The reference monitor is currently reconfigurable in both ON and OFF modes."; \
              elif [ "$$rec_on" -eq 0 ] && [ "$$rec_off" -eq 0 ]; then \
                  echo "The reference monitor is currently not reconfigurable and is in its default state."; \
              elif [ "$$rec_on" -eq 1 ] && [ "$$rec_off" -eq 0 ]; then \
                  echo "The reference monitor is currently reconfigurable only in ON mode."; \
              elif [ "$$rec_on" -eq 0 ] && [ "$$rec_off" -eq 1 ]; then \
                  echo "The reference monitor is currently reconfigurable only in OFF mode."; \
              else \
                  echo "Unable to determine the configuration state of the reference monitor."; \
              fi'

