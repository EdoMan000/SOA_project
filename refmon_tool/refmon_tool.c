/*
 * 
 * @file refmon_tool.c 
 * @brief This is a simple CLI tool to interact with the refmon module
 * 
 * NB:] Make sure to run "make up" before running this code.
 *
 * @author Edoardo Manenti
 *
 * @date March, 2024 
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include "syscall_nums.h"

// ANSI color codes
#define RED "\x1B[31m"
#define GREEN "\x1B[32m"
#define YELLOW "\x1B[33m"
#define RESET "\x1B[0m"

typedef enum {
    REFMON_ACTION_PROTECT,
    REFMON_ACTION_UNPROTECT
} refmon_action_t;

int read_menu_option() {
    char input[256];
    char *endptr;
    long val;

    if (fgets(input, sizeof(input), stdin) != NULL) {
        errno = 0; 
        val = strtol(input, &endptr, 10);

        if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
                || (errno != 0 && val == 0)) {
            return -1; 
        }

        if (endptr == input) {
            return -1; 
        }

        // If we got here, strtol() successfully parsed a number

        if (*endptr != '\n') {
            return -1; 
        }

        return (int)val;
    }
    return -1; 
}

char last_output[4096] = ""; 

static void retrieve_shell_cmd_output(char *cmd, char* err_msg,  char* res_msg){
    char cmd_output[1024] = {0};
    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        snprintf(last_output, sizeof(last_output), RED "Failed to run command.\n\n" RESET);
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), fp) != NULL) {
        strncat(cmd_output, line, sizeof(cmd_output) - strlen(cmd_output) - 1);
    }
    pclose(fp);
    if (strlen(cmd_output) == 0 || strcmp(cmd_output,"\nTHIS IS THE REFERENCE MONONITOR INTRUSIONS LOG FILE.\n\n") == 0) {
        snprintf(last_output, sizeof(last_output), RED "%s\n\n" RESET, err_msg);
        return;
    }
    snprintf(last_output, sizeof(last_output), "[RES:]%s:\n\n%s\n\n", res_msg, cmd_output);
    return;
}

static int invoke_refmon_manage(int action) {
    return syscall(__NR_sys_refmon_manage, action);
}

static int invoke_refmon_reconfigure(refmon_action_t action, const char* password, const char* path) {
    return syscall(__NR_sys_refmon_reconfigure, action, password, path);
}

int main(int argc, char** argv) {

    while (1) {
        system("clear"); 

        printf(YELLOW "██████╗ ███████╗███████╗███╗   ███╗ ██████╗ ███╗   ██╗    ████████╗ ██████╗  ██████╗ ██╗     \n" RESET);
		printf(YELLOW "██╔══██╗██╔════╝██╔════╝████╗ ████║██╔═══██╗████╗  ██║    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     \n" RESET);
		printf(YELLOW "██████╔╝█████╗  █████╗  ██╔████╔██║██║   ██║██╔██╗ ██║       ██║   ██║   ██║██║   ██║██║     \n" RESET);
		printf(YELLOW "██╔══██╗██╔══╝  ██╔══╝  ██║╚██╔╝██║██║   ██║██║╚██╗██║       ██║   ██║   ██║██║   ██║██║     \n" RESET);
		printf(YELLOW "██║  ██║███████╗██║     ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║       ██║   ╚██████╔╝╚██████╔╝███████╗\n" RESET);
		printf(YELLOW "╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝\n\n" RESET);

		printf(YELLOW "       D E V E L O P E D    B Y     Edoardo Manenti [ 0333574 | manenti000@gmail.com ]       \n" RESET);
		printf("\n\n");


        printf(YELLOW "Choose an option:\n" RESET);
        printf(YELLOW "[1] Manage reference monitor state\n" RESET);
        printf(YELLOW "[2] Reconfigure reference monitor\n" RESET);
        printf(YELLOW "[3] Print dmesg tail (requires EUID 0)\n" RESET);
        printf(YELLOW "[4] Print last intrusion from log\n" RESET);
        printf(YELLOW "[5] Exit\n\n" RESET);
        printf("[NB:] The intrusions log can be accessed at '/tmp/refmon_log/the-refmon-log' at any time!\n\n");
        printf("%s", last_output); // Display the last output message
        printf(YELLOW ">>> " RESET);

        int result;
        int option = read_menu_option(); 
        if (option == -1) {
            snprintf(last_output, sizeof(last_output), RED "Invalid option. Please enter a valid number.\n\n" RESET);
            continue; 
        }

        switch (option) {
            case 1:
                printf(YELLOW "\nEnter new state:\n" RESET);
                printf(YELLOW "[0] OFF\n" RESET);
                printf(YELLOW "[1] ON\n" RESET);
                printf(YELLOW "[2] REC-OFF\n" RESET);
                printf(YELLOW "[3] REC-ON\n" RESET);
                printf(YELLOW "[4] QUERY_STATE\n\n" RESET);
                printf(YELLOW ">>> " RESET);
                int newState = read_menu_option(); 
                if (newState == -1) {
                    snprintf(last_output, sizeof(last_output), RED "Invalid option. Please enter a valid number.\n\n" RESET);
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
                getchar();
                result = invoke_refmon_reconfigure(action_t, password, path);
                break;
            case 3:
                retrieve_shell_cmd_output("dmesg | tail -n 10", "Failed to retrieve output. (Check if running tool with EUID set to 0)", "'sudo dmesg' tail output");
                result = 12345;
                break;
            case 4:
                retrieve_shell_cmd_output("cat /tmp/refmon_log/the-refmon-log | tail -n 9", "No intrusions available in log.", "Last intrusion event");
                result = 12345;
                break;
            case 5:
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

