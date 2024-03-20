#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

typedef enum {
    REFMON_ACTION_PROTECT,
    REFMON_ACTION_UNPROTECT
} refmon_action_t;

#ifndef __NR_refmon_manage
#define __NR_refmon_manage 134
#endif

#ifndef __NR_refmon_reconfigure
#define __NR_refmon_reconfigure 156
#endif

int main(int argc, char** argv)
{
	//default values for password and path to test
	char* passw = "Th15_I5_4_t3s7_p4s5W0rd"; 
	char* path = "/home/manenti_0333574/Scaricati/test.txt";

	if (argc < 3) {
		printf("Usage: %s <syscall_code> <param1> [optional]<param2> <param3>...\n", argv[0]);
		return 1;
	}
	int syscall_code = atoi(argv[1]);

	switch (syscall_code) {
		case __NR_refmon_manage:
			int state_code = atoi(argv[2]);
			return syscall(syscall_code, state_code);
			break;
		case __NR_refmon_reconfigure:
			refmon_action_t action;
			if (strcmp(argv[2], "protect") == 0) {
					action = REFMON_ACTION_PROTECT;
			} else if (strcmp(argv[2], "unprotect") == 0) {
					action = REFMON_ACTION_UNPROTECT;
			} else {
					fprintf(stderr, "Invalid action: %s\n", argv[2]);
					return EXIT_FAILURE;
			}
			if (argc >= 4)
				passw = argv[3];
			if (argc >= 5)
				path = argv[4];
			return syscall(syscall_code, action, passw, path);
		default:
			printf("Invalid syscall_code. No action performed.\n");
			return -1;
	}
}
