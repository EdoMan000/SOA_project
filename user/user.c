#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//this is for copy-paste during testing:
// Th15_I5_4_t3s7_p4s5W0rd
// /home/manenti_0333574/Scaricati/test.txt

// ANSI color codes
#define RED "\x1B[31m"
#define GREEN "\x1B[32m"
#define YELLOW "\x1B[33m"
#define RESET "\x1B[0m"

#define REFMON_MANAGE_SYSCALL 134 // syscall number for refmon_manage
#define REFMON_RECONFIGURE_SYSCALL 156 // syscall number for refmon_reconfigure

typedef enum {
    REFMON_ACTION_PROTECT,
    REFMON_ACTION_UNPROTECT
} refmon_action_t;

int invoke_refmon_manage(int action);
int invoke_refmon_reconfigure(refmon_action_t action, const char* password, const char* path);

int main(int argc, char** argv) {
    char last_output[256] = ""; 

    while (1) {
        system("clear"); 

        printf(YELLOW "██████╗ ███████╗███████╗███╗   ███╗ ██████╗ ███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     \n" RESET);
		printf(YELLOW "██╔══██╗██╔════╝██╔════╝████╗ ████║██╔═══██╗████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     \n" RESET);
		printf(YELLOW "██████╔╝█████╗  █████╗  ██╔████╔██║██║   ██║██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     \n" RESET);
		printf(YELLOW "██╔══██╗██╔══╝  ██╔══╝  ██║╚██╔╝██║██║   ██║██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     \n" RESET);
		printf(YELLOW "██║  ██║███████╗██║     ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗\n" RESET);
		printf(YELLOW "╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝\n\n" RESET);

		printf(YELLOW "     D E V E L O P E D    B Y       EdoMan000 [ 0333574 | manenti000@gmail.com ]             \n" RESET);
		printf("\n\n");


        printf(YELLOW "Choose an option:\n" RESET);
        printf(YELLOW "1. Manage reference monitor state\n" RESET);
        printf(YELLOW "2. Reconfigure reference monitor\n" RESET);
        printf(YELLOW "3. Exit\n\n" RESET);
        printf("[NB:] The log of illegal accesses to protected files/directories can be accessed at\n     '/tmp/refmon_log/the-refmon-log' at any time!\n\n");
        printf("%s", last_output); // Display the last output message
        printf(YELLOW ">>> " RESET);

        int option, result;
        scanf("%d", &option);
        getchar(); 

        switch (option) {
            case 1:
                printf(YELLOW "\nEnter new state (0: OFF, 1: ON, 2: REC-OFF, 3: REC-ON, 4: QUERY_STATE): " RESET);
                int newState;
                scanf("%d", &newState);
                if(newState > 4 || newState < 0){
                    snprintf(last_output, sizeof(last_output), RED "Invalid state: %d\n\n" RESET, newState);
                    result = 12345;
                    break;
                }
                result = invoke_refmon_manage(newState);
                break;
            case 2:
                char action[10], password[256], path[256];
                printf(YELLOW "\nEnter action (protect/unprotect): " RESET);
                scanf("%s", action);
                refmon_action_t action_t = strcmp(action, "protect") == 0 ? REFMON_ACTION_PROTECT : REFMON_ACTION_UNPROTECT;
                printf(YELLOW "Enter password: " RESET);
                scanf("%s", password);
                printf(YELLOW "Enter path: " RESET);
                scanf("%s", path);
                result = invoke_refmon_reconfigure(action_t, password, path);
                break;
            case 3:
                printf(RED "\nBye bye...\n" RESET);
                return EXIT_SUCCESS;
            default:
                snprintf(last_output, sizeof(last_output), RED "Invalid option: %d\n\n" RESET, option);
                result = 12345;
        }

        // Update the last output message based on the operation result
        if (result == 0) {
            snprintf(last_output, sizeof(last_output), GREEN "[RES:] Last operation completed successfully. Please check 'sudo dmesg' for more details.\n\n" RESET);
        } else if (result != 12345) {
            snprintf(last_output, sizeof(last_output), RED "[RES:] Last operation did not complete successfully. Please check 'sudo dmesg' for more details.\n\n" RESET);
        }
    }
}

int invoke_refmon_manage(int action) {
    return syscall(REFMON_MANAGE_SYSCALL, action);
}

int invoke_refmon_reconfigure(refmon_action_t action, const char* password, const char* path) {
    return syscall(REFMON_RECONFIGURE_SYSCALL, action, password, path);
}
