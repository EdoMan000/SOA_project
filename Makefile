obj-m += the_reference-monitor.o
the_reference-monitor-objs += reference-monitor.o lib/scth.o utils/sha256_utils.o utils/general_utils.o
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
		echo "Mounting reference-monitor module..." && { sudo insmod the_reference-monitor.ko the_syscall_table=$$(sudo cat /sys/module/the_usctm/parameters/sys_call_table_address) the_refmon_secret=$$(sudo cat the_secret) > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,reference-monitor,mount); } \
	elif [ "$1" = "usctm" ]; then \
		echo "Mounting usctm module..." && { cd the_usctm && sudo insmod the_usctm.ko > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,usctm,mount); } \
	else \
		echo "Mounting singlefilefs module..." && { cd singlefile-FS && sudo insmod singlefilefs.ko > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,singlefilefs,mount); } \
	fi
endef

define rmmod_module
	@if [ "$2" = "singlefilefs" ]; then \
		echo "Unmounting $2 module..." && { cd $1 && sudo rmmod $2.ko > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,$2,unmount); } \
	else \
		echo "Unmounting $2 module..." && { cd $1 && sudo rmmod the_$2.ko > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,$2,unmount); } \
	fi
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

define compile_singlefilemakefs
	@echo "Compiling singlefilemakefs code..." && cd singlefile-FS && gcc singlefilemakefs.c -o singlefilemakefs && echo "singlefilemakefs code compilation successful!";
endef

define init_singlefilefs
	@echo "Initializing singlefilefs..." && cd singlefile-FS && echo "---------------------------------------------" && dd bs=4096 count=100 if=/dev/zero of=image && ./singlefilemakefs image && mkdir /tmp/refmon_log && echo "singlefilefs initialized successfully!";
endef

define clean_singlefilefs
	@echo "Cleaning singlefilefs module..." && rm -r /tmp/refmon_log && cd singlefile-FS && rm singlefilemakefs && rm image && { make -C /lib/modules/$$(uname -r)/build M=$(PWD)/singlefile-FS clean > $(TMP_FILE) 2>&1; EXIT_CODE=$$?; $(call handle_exit_code,$$EXIT_CODE,singlefilefs,clean); }
endef

define mount_singlefilefs
	@echo "Mounting singlefilefs FS..." && cd singlefile-FS && sudo mount -o loop -t singlefilefs image /tmp/refmon_log/ && echo "singlefilefs FS successfully mounted!";
endef

define unmount_singlefilefs
	@echo "Unmounting singlefilefs FS..." && cd singlefile-FS && sudo umount /tmp/refmon_log/ && echo "singlefilefs FS successfully unmounted!";
endef

define compile_refmon_tool
	@echo "Compiling refmon_tool..." && cd refmon_tool && echo "//syscall number for sys_refmon_manage\n#define __NR_sys_refmon_manage $$(cat /sys/module/the_reference_monitor/parameters/__NR_sys_refmon_manage)\n//syscall number for sys_refmon_reconfigure\n#define __NR_sys_refmon_reconfigure $$(cat /sys/module/the_reference_monitor/parameters/__NR_sys_refmon_reconfigure)\n" > syscall_nums.h && gcc refmon_tool.c -o ../refmon_tool_run && echo "refmon_tool compilation successful!";
endef

define clean_refmon_tool
	@echo "Cleaning refmon_tool..." && rm refmon_tool_run && echo "refmon_tool cleaning successful!";
endef

define compile_refmon_test
	@echo "Compiling refmon_test..." && cd refmon_test && echo "//syscall number for sys_refmon_manage\n#define __NR_sys_refmon_manage $$(cat /sys/module/the_reference_monitor/parameters/__NR_sys_refmon_manage)\n//syscall number for sys_refmon_reconfigure\n#define __NR_sys_refmon_reconfigure $$(cat /sys/module/the_reference_monitor/parameters/__NR_sys_refmon_reconfigure)\n" > syscall_nums.h && gcc refmon_test.c -o ../refmon_test_run && gcc baseline_test.c -o ../baseline_test_run && echo "refmon_test compilation successful!";
endef

define clean_refmon_test
	@echo "Cleaning refmon_test..." && rm refmon_test_run && rm -rf refmon_test/protected && rm -rf refmon_test/tests && rm -rf refmon_test/graphs && rm -rf refmon_test/results  && echo "refmon_test cleaning successful!";
endef

up: all mount tool test
	@echo "REFMON IS UP.\n\n You can now run 'sudo ./refmon_tool_run' to access the CLI for RefMon.\n You can also run 'python3 ./test_refmon.py' to access the CLI for RefMon tests.\n\nNB:] beware of using sudo because EUID 0 is required.\n\n"

down: unmount clean
	@echo "REFMON IS DOWN.\n\n"

all:
	$(call build_module,the_usctm,usctm)
	$(call build_module,.,reference-monitor)
	$(call compile_singlefilemakefs)
	$(call build_module,singlefile-FS,singlefilefs)
	$(call init_singlefilefs)

tool:
	$(call compile_refmon_tool)

test:
	$(call compile_refmon_test)

clean:
	$(call clean_module,the_usctm,usctm)
	$(call clean_module,.,reference-monitor)
	$(call clean_singlefilefs)
	$(call clean_refmon_tool)
	$(call clean_refmon_test)

mount:
	$(call insmod_module,usctm)
	$(call insmod_module,reference-monitor)
	$(call insmod_module,singlefilefs)
	$(call mount_singlefilefs)

unmount:
	$(call rmmod_module,the_usctm,usctm)
	$(call rmmod_module,.,reference-monitor)
	$(call unmount_singlefilefs)
	$(call rmmod_module,singlefile-FS,singlefilefs)

check:
	$(call check_reconfigurability)

enable:
	$(call set_parameter,the_refmon_reconf,1)

disable:
	$(call set_parameter,the_refmon_reconf,0)
