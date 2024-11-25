/*
 * @file refmon_test.c 
 * 
 * @brief A user-space test to compute overhead 
 *        introduced by refmon security operations
 * 
 * @author Edoardo Manenti
 *
 * @date November, 2024 
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include "syscall_nums.h"

typedef enum {
    REFMON_ACTION_PROTECT,
    REFMON_ACTION_UNPROTECT
} refmon_action_t;

enum refmon_ops {
    REFMON_SET_OFF = 0,
    REFMON_SET_ON = 1,
    REFMON_SET_REC_OFF = 2,
    REFMON_SET_REC_ON = 3,
    REFMON_STATE_QUERY = 4
};

#define PATH_TTL -1 // Infinite TTL for protection
#define M 100 // Number of test files for read/write operations
#define NUM_RUNS 10 // Number of runs to average the times
#define MAX_PASSW_LEN 32
#define PATH_MAX 4096

static int verbose = 0; // Global variable for verbosity control

static int invoke_refmon_manage(int action) {
    return syscall(__NR_sys_refmon_manage, action);
}

static int invoke_refmon_reconfigure(refmon_action_t action, const char* password, const char* path, int ttl) {
    return syscall(__NR_sys_refmon_reconfigure, action, password, path, ttl);
}

// Function to create a file with some content
int create_file(const char *filename)
{
    if (verbose) printf("Creating file: %s\n", filename);
    int fd = open(filename, O_CREAT | O_WRONLY, 0644);
    if (fd < 0)
    {
        perror("open");
        return -1;
    }
    const char *content = "This is some test content.\n";
    write(fd, content, strlen(content));
    close(fd);
    return 0;
}

// Function to read a file
int read_file(const char *filename)
{
    if (verbose) printf("Reading file: %s\n", filename);
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        perror("open");
        return -1;
    }
    char buffer[1024];
    read(fd, buffer, sizeof(buffer));
    close(fd);
    return 0;
}

// Function to write to a file
int write_file(const char *filename)
{
    if (verbose) printf("Writing to file: %s\n", filename);
    int fd = open(filename, O_WRONLY | O_APPEND);
    if (fd < 0)
    {
        perror("open");
        return -1;
    }
    const char *content = "Appending some content.\n";
    write(fd, content, strlen(content));
    close(fd);
    return 0;
}

// Function to pre-open a file to load it into cache
void pre_open_file(const char *filename)
{
    if (verbose) printf("Pre-loading file into cache: %s\n", filename);
    int fd = open(filename, O_RDONLY);
    if (fd >= 0)
    {
        char buffer[1024];
        read(fd, buffer, sizeof(buffer));
        close(fd);
    }
}

// Function to delete all files in a directory and the directory itself
void cleanup_test_directory(const char *dirpath)
{
    if (verbose) printf("Cleaning up test directory: %s\n", dirpath);
    DIR *dir = opendir(dirpath);
    if (dir)
    {
        struct dirent *entry;
        char filepath[512];
        while ((entry = readdir(dir)) != NULL)
        {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);
            if (verbose) printf("Removing file: %s\n", filepath);
            remove(filepath);
        }
        closedir(dir);
    }
    rmdir(dirpath);
}

// Main test function
int main(int argc, char *argv[])
{
    // Parse command-line arguments
    int opt;
    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
            case 'v':
                verbose = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-v]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    int N_values[] = {0, 10, 100, 1000}; // Varying sizes of the protected set
    int N_tests = sizeof(N_values)/sizeof(N_values[0]);
    char filename[PATH_MAX];
    int i, j, k;
    struct timespec start_time, end_time;
    double elapsed_time;
    char password[MAX_PASSW_LEN + 1];
    char *test_dir = "./refmon_test/tests";
    struct stat st = {0};

    double read_times[N_tests];
    double write_times[N_tests];
    double read_baseline = 0.0;
    double write_baseline = 0.0;
    FILE *csv_file;

    // Read password from 'the_secret' file
    FILE *pass_file = fopen("the_secret", "r");
    if (!pass_file)
    {
        perror("fopen the_secret");
        exit(EXIT_FAILURE);
    }
    if (!fgets(password, sizeof(password), pass_file))
    {
        perror("fgets");
        fclose(pass_file);
        exit(EXIT_FAILURE);
    }
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n')
        password[len - 1] = '\0';
    fclose(pass_file);

    invoke_refmon_manage(REFMON_SET_REC_ON);
    if (stat(test_dir, &st) == -1 && mkdir(test_dir, 0700) != 0)
    {
        perror("mkdir test_dir");
        exit(EXIT_FAILURE);
    }

    for (i = 0; i < M; i++)
    {
        snprintf(filename, sizeof(filename), "%s/test_file_%d", test_dir, i);
        create_file(filename);
    }

    csv_file = fopen("results.csv", "w");
    if (!csv_file)
    {
        perror("fopen results.csv");
        exit(EXIT_FAILURE);
    }
    fprintf(csv_file, "N,Read Time (ns),Read Overhead (%%),Write Time (ns),Write Overhead (%%)\n");

    for (j = 0; j < N_tests; j++)
    {
        int N = N_values[j];
        if (verbose) printf("\nTesting with N = %d protected files\n", N);

        if (N > 0)
        {
            for (i = 0; i < N; i++)
            {
                snprintf(filename, sizeof(filename), "%s/protected_file_%d", test_dir, i);
                create_file(filename);
                if (verbose) printf("Protecting file: %s\n", filename);
                if (invoke_refmon_reconfigure(REFMON_ACTION_PROTECT, password, filename, PATH_TTL) < 0)
                {
                    fprintf(stderr, "Failed to protect file: %s\n", filename);
                }
            }
        }

        // Measure single operation times
        double total_read_time = 0.0;
        double total_write_time = 0.0;

        for (k = 0; k < NUM_RUNS; k++)
        {
            for (i = 0; i < M; i++)
            {
                snprintf(filename, sizeof(filename), "%s/test_file_%d", test_dir, i);

                // Time for single read operation
                pre_open_file(filename);
                clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
                read_file(filename);
                clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
                elapsed_time = (end_time.tv_sec - start_time.tv_sec) * 1e9  +
                               (end_time.tv_nsec - start_time.tv_nsec);
                total_read_time += elapsed_time;
                //if(i==0 && k ==0) printf("\n[%d] READ TIME: %f\n",j,elapsed_time);

                // Time for single write operation
                pre_open_file(filename);
                clock_gettime(CLOCK_MONOTONIC_RAW, &start_time);
                write_file(filename);
                clock_gettime(CLOCK_MONOTONIC_RAW, &end_time);
                elapsed_time = (end_time.tv_sec - start_time.tv_sec) * 1e9  +
                               (end_time.tv_nsec - start_time.tv_nsec);
                total_write_time += elapsed_time;
                //if(i==0 && k ==0) printf("[%d] WRITE TIME: %f\n",j,elapsed_time);
            }
        }

        // Compute averages
        read_times[j] = total_read_time / (NUM_RUNS * M);
        write_times[j] = total_write_time / (NUM_RUNS * M);

        if (N == 0) {
            read_baseline = read_times[j];
            write_baseline = write_times[j];
        }

        double read_overhead = (read_times[j] - read_baseline) / read_baseline * 100.0;
        if (read_overhead < 0)
        {
            read_overhead = 0;
        }
        double write_overhead = (write_times[j] - write_baseline) / write_baseline * 100.0;
        if (write_overhead < 0)
        {
            write_overhead = 0;
        }

        fprintf(csv_file, "%d,%f,%f,%f,%f\n", N, read_times[j], read_overhead, write_times[j], write_overhead);

        if (N > 0)
        {
            for (i = 0; i < N; i++)
            {
                snprintf(filename, sizeof(filename), "%s/protected_file_%d", test_dir, i);
                if (verbose) printf("Unprotecting file: %s\n", filename);
                if (invoke_refmon_reconfigure(REFMON_ACTION_UNPROTECT, password, filename, PATH_TTL) > 0)
                {
                    fprintf(stderr, "Failed to unprotect file: %s\n", filename);
                }
                remove(filename);
            }
        }
    }

    fclose(csv_file);
    cleanup_test_directory(test_dir);
    invoke_refmon_manage(REFMON_SET_OFF);
    printf("Results saved to results.csv\n");
    return 0;
}
