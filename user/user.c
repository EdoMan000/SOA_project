#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

int main(int argc, char** argv)
{
	char* passw = "Th15_I5_4_t3s7_p4s5W0rd";
    char* path = "/home/manenti_0333574/Scaricati";

	if (argc < 3) {
        printf("Usage: %s <syscall_code> [optional]<param1> <param2> ...\n", argv[0]);
        return 1;
    }
    int syscall_code = atoi(argv[1]);

	switch (syscall_code) {
        case 134:
    		int state_code = atoi(argv[2]);
			return syscall(syscall_code, state_code);
            break;
        case 174:
			if (argc >= 3)
				passw = argv[2];
			if (argc >= 4)
				path = argv[3];
			return syscall(syscall_code, passw, path);
        case 177:
			if (argc >= 3)
				passw = argv[2];
			if (argc >= 4)
				path = argv[3];
			return syscall(syscall_code, passw, path);
        default:
            printf("Invalid syscall_code. No action performed.\n");
            return -1;
    }
}
