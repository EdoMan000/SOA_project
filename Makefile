obj-m += the_reference-monitor.o
the_reference-monitor-objs += reference-monitor.o lib/scth.o utils/sha256_utils.o
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
		echo "Mounting reference-monitor module..." && { sudo insmod the_reference-monitor.ko the_syscall_table=$$(sudo cat /sys/module/the_usctm/parameters/sys_call_table_address) the_refmon_secret=$$(sudo cat secret) > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,reference-monitor,mount); } \
	else \
		echo "Mounting usctm module..." && { cd the_usctm && sudo insmod the_usctm.ko > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,usctm,mount); } \
	fi
endef

define rmmod_module
	@echo "Unmounting $2 module..." && { cd $1 && sudo rmmod the_$2.ko > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,$2,unmount); }
endef

define check_reconfigurability
	@sudo bash -c 'rec="$$(cat /sys/module/the_reference_monitor/parameters/the_refmon_reconf 2>/dev/null)"; \
              if [ "$$rec" -eq 1 ]; then \
                  echo "The reference monitor is currently reconfigurable."; \
              elif [ "$$rec" -eq 0 ]; then \
                  echo "The reference monitor is currently not reconfigurable."; \
              else \
                  echo "Unable to determine the reconfigurability of the reference monitor."; \
                  echo "Error: UNKNOWN_REC_STATE_VAL -> $$rec"; \
              fi'
endef

define set_parameter
	@rec="$$(sudo bash -c 'cat /sys/module/the_reference_monitor/parameters/the_refmon_reconf 2>/dev/null || echo "error"')"; \
	if [ "$$rec" != "error" ]; then \
		if [ "$$rec" -ne $(2) ]; then \
			sudo bash -c 'echo "$(2)" > /sys/module/the_reference_monitor/parameters/the_refmon_reconf'; \
			if [ "$(2)" = "1" ]; then \
				echo "The reference monitor can now be reconfigured"; \
			else \
				echo "The reference monitor can no longer be reconfigured"; \
			fi \
		else \
			if [ "$(2)" = "1" ]; then \
				echo "Warning: The reconfiguration for the reference monitor is already enabled"; \
			else \
				echo "Warning: The reconfiguration for the reference monitor is already disabled"; \
			fi \
		fi \
	else \
		echo "Error: Unable to read the reconfiguration state of the reference monitor. Check if module is mounted."; \
	fi
endef

define compile_user
	@echo "Compiling user code..." && cd user && gcc user.c -o ../user.out && echo "user code compilation successful!";
endef

define clean_user
	@echo "Cleaning user code..." && rm user.out && echo "user code cleaning successful!";
endef

all:
	$(call build_module,the_usctm,usctm)
	$(call build_module,.,reference-monitor)
	$(call compile_user)

clean:
	$(call clean_module,the_usctm,usctm)
	$(call clean_module,.,reference-monitor)
	$(call clean_user)

mount:
	$(call insmod_module,usctm)
	$(call insmod_module,reference-monitor)

unmount:
	$(call rmmod_module,the_usctm,usctm)
	$(call rmmod_module,.,reference-monitor)

check:
	$(call check_reconfigurability)

enable:
	$(call set_parameter,the_refmon_reconf,1)

disable:
	$(call set_parameter,the_refmon_reconf,0)

