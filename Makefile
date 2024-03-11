obj-m += the_reference-monitor.o
the_reference-monitor-objs += reference-monitor.o lib/scth.o
TMP_FILE := makefile_out.tmp



define handle_exit_code
	if [ "$$EXIT_CODE" -eq 0 ]; then \
		echo "$2 module $3 successful!"; \
		rm -f $(TMP_FILE); \
	else \
		echo "Error: Failed to $3 $2 module"; \
		cat $(TMP_FILE); \
		rm -f $(TMP_FILE); \
		exit $$EXIT_CODE; \
	fi
endef

define build_module
	@echo "Building $2 module..." && { make -C /lib/modules/$$(uname -r)/build M=$(PWD)/$1 modules > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,$2,build); }
endef

define clean_module
	@echo "Cleaning $2 module..." && { make -C /lib/modules/$$(uname -r)/build M=$(PWD)/$1 clean > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,$2,clean); }
endef

define insmod_module
	@if [ "$1" = "reference-monitor" ]; then \
		echo "Mounting reference-monitor module..." && { sudo insmod the_reference-monitor.ko the_syscall_table=$$(sudo cat /sys/module/the_usctm/parameters/sys_call_table_address) > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,reference-monitor,mount); } \
	else \
		echo "Mounting usctm module..." && { cd usctm && sudo insmod the_usctm.ko > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,usctm,mount); } \
	fi
endef

define rmmod_module
	@echo "Unmounting $2 module..." && { cd $1 && sudo rmmod the_$2.ko > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,$2,unmount); }
endef

define check_rec
	@sudo bash -c 'rec_on="$$(cat /sys/module/the_reference_monitor/parameters/enable_rec_on 2>/dev/null)"; \
              rec_off="$$(cat /sys/module/the_reference_monitor/parameters/enable_rec_off 2>/dev/null)"; \
              if [ "$$rec_on" -eq 1 ] && [ "$$rec_off" -eq 1 ]; then \
                  echo "The reference monitor is currently reconfigurable in both ON and OFF modes."; \
              elif [ "$$rec_on" -eq 0 ] && [ "$$rec_off" -eq 0 ]; then \
                  echo "The reference monitor is currently not reconfigurable."; \
              elif [ "$$rec_on" -eq 1 ] && [ "$$rec_off" -eq 0 ]; then \
                  echo "The reference monitor is currently reconfigurable only in ON mode."; \
              elif [ "$$rec_on" -eq 0 ] && [ "$$rec_off" -eq 1 ]; then \
                  echo "The reference monitor is currently reconfigurable only in OFF mode."; \
              else \
                  echo "Unable to determine the configuration state of the reference monitor."; \
              fi'
endef

define set_parameter
	@rec_value="$$(sudo bash -c 'cat /sys/module/the_reference_monitor/parameters/$(1) 2>/dev/null || echo "error"')"; \
	if [ "$$rec_value" != "error" ]; then \
		if [ "$$rec_value" -ne $(2) ]; then \
			sudo bash -c 'echo "$(2)" > /sys/module/the_reference_monitor/parameters/$(1)'; \
			if [ "$(2)" = "1" ]; then \
				echo "The reference monitor can now be reconfigured in $(3) mode"; \
			else \
				echo "The reference monitor can no longer be reconfigured in $(3) mode"; \
			fi \
		else \
			if [ "$(2)" = "1" ]; then \
				echo "Warning: The reconfiguration for the reference monitor is already enabled in $(3) mode"; \
			else \
				echo "Warning: The reconfiguration for the reference monitor is already disabled in $(3) mode"; \
			fi \
		fi \
	else \
		echo "Error: Unable to read the reconfiguration state of the reference monitor."; \
	fi
endef



all:
	$(call build_module,usctm,usctm)
	$(call build_module,.,reference-monitor)

clean:
	$(call clean_module,usctm,usctm)
	$(call clean_module,.,reference-monitor)

mount:
	$(call insmod_module,usctm)
	$(call insmod_module,reference-monitor)

unmount:
	$(call rmmod_module,usctm,usctm)
	$(call rmmod_module,.,reference-monitor)

check_rec:
	$(call check_rec)

enable_rec_on:
	$(call set_parameter,enable_rec_on,1,ON)

enable_rec_off:
	$(call set_parameter,enable_rec_off,1,OFF)

disable_rec_on:
	$(call set_parameter,enable_rec_on,0,ON)

disable_rec_off:
	$(call set_parameter,enable_rec_off,0,OFF)

enable_rec_all:
	$(call set_parameter,enable_rec_on,1,ON)
	$(call set_parameter,enable_rec_off,1,OFF)

disable_rec_all:
	$(call set_parameter,enable_rec_on,0,ON)
	$(call set_parameter,enable_rec_off,0,OFF)

