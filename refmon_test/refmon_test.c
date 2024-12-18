/*
 * @file refmon_test.c 
 * 
 * @brief A user-space test to compute overhead 
 *        introduced by refmon security operations, using uint64_t.
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
#include <stdint.h> // For uint64_t
#include <pthread.h>

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
#define M 1         // Number of test files for read/write operations
#define N_RUNS 1000 // Number of test runs per operation
#define MAX_PASSW_LEN 32
#define PATH_MAX 4096

typedef struct {
    int thread_id;
    int n_runs;
    int m_files;
    char read_dir[PATH_MAX];
    char write_dir[PATH_MAX];
    char create_dir[PATH_MAX];
    uint64_t total_read_time;
    uint64_t total_write_time;
    uint64_t total_create_time;
    int valid_read_count;
    int valid_write_count;
    int valid_create_count;
} thread_data_t;

static int verbose = 0; // Global variable for verbosity control

static int invoke_refmon_manage(int action) {
    return syscall(__NR_sys_refmon_manage, action);
}

static int invoke_refmon_reconfigure(int action, const char* password, const char* path, int ttl) {
    return syscall(__NR_sys_refmon_reconfigure, action, password, path, ttl);
}

// Function to read TSC (Time Stamp Counter)
static inline uint64_t rdtsc() {
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

// Function to create a file with some content
int create_file(const char *filename) {
    if (verbose) printf("Creating file: %s\n", filename);
    int fd = open(filename, O_CREAT | O_WRONLY, 0666);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    const char *content = "This is some test content.\n";
    write(fd, content, strlen(content));
    close(fd);
    return 0;
}

// Function to measure opening a file in write mode
uint64_t single_file_create(const char *filename, int iteration) {
    char new_file[PATH_MAX];
    snprintf(new_file, sizeof(new_file), "%s_%d", filename, iteration);

    uint64_t start_cycles, end_cycles;

    if (verbose) printf("Opening file for creation: %s\n", new_file);

    start_cycles = rdtsc();
    int fd = open(new_file, O_CREAT | O_WRONLY | O_TRUNC, 0666);
    end_cycles = rdtsc();

    if (fd < 0) {
        perror("file creation failed");
        return (uint64_t)-1;
    }

    close(fd);
    remove(new_file); // Clean up the file after timing
    return end_cycles - start_cycles;
}

// Function to measure opening a file in read mode
uint64_t single_open_read(const char *filename) {
    uint64_t start_cycles, end_cycles;

    if (verbose) printf("Opening file for reading: %s\n", filename);

    start_cycles = rdtsc();
    int fd = open(filename, O_RDONLY);
    end_cycles = rdtsc();

    if (fd < 0) {
        perror("open for reading failed");
        return (uint64_t)-1;
    }

    close(fd);
    return end_cycles - start_cycles;
}

// Function to measure opening a file in write mode
uint64_t single_open_write(const char *filename) {
    uint64_t start_cycles, end_cycles;

    if (verbose) printf("Opening file for writing: %s\n", filename);

    start_cycles = rdtsc();
    int fd = open(filename, O_WRONLY);
    end_cycles = rdtsc();

    if (fd < 0) {
        perror("open for writing failed");
        return (uint64_t)-1;
    }

    close(fd);
    return end_cycles - start_cycles;
}

// Function to delete all files in a directory and the directory itself
void cleanup_directory(const char *dirpath) {
    if (verbose) printf("Cleaning up test directory: %s\n", dirpath);
    DIR *dir = opendir(dirpath);
    if (dir) {
        struct dirent *entry;
        char filepath[512];
        while ((entry = readdir(dir)) != NULL) {
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

void* thread_test_function(void* arg) {
    thread_data_t* data = (thread_data_t*)arg;
    char filename[PATH_MAX];

    for (int k = 0; k < data->n_runs; k++) {
        for (int i = 0; i < data->m_files; i++) {
            int ret = snprintf(filename, sizeof(filename), "%s/test_file_%d_thread_%d", data->read_dir, i, data->thread_id);
            if (ret >= sizeof(filename)) {
                fprintf(stderr, "Error: filename too long, truncated.\n");
                pthread_exit(NULL);
            }
            create_file(filename);

            // Measure read time
            uint64_t read_time = single_open_read(filename);
            if (read_time != (uint64_t)-1) {
                data->total_read_time += read_time;
                data->valid_read_count++;
            }
        }
        for (int i = 0; i < data->m_files; i++) {
            int ret = snprintf(filename, sizeof(filename), "%s/test_file_%d_thread_%d", data->write_dir, i, data->thread_id);
            if (ret >= sizeof(filename)) {
                fprintf(stderr, "Error: filename too long, truncated.\n");
                pthread_exit(NULL);
            }
            create_file(filename);

            // Measure write time
            uint64_t write_time = single_open_write(filename);
            if (write_time != (uint64_t)-1) {
                data->total_write_time += write_time;
                data->valid_write_count++;
            }
        }
        for (int i = 0; i < data->m_files; i++) {
            int ret = snprintf(filename, sizeof(filename), "%s/test_file_%d_thread_%d", data->create_dir, i, data->thread_id);
            if (ret >= sizeof(filename)) {
                fprintf(stderr, "Error: filename too long, truncated.\n");
                pthread_exit(NULL);
            }

            // Measure file creation time
            uint64_t create_time = single_file_create(filename, k);
            if (create_time != (uint64_t)-1) {
                data->total_create_time += create_time;
                data->valid_create_count++;
            }
        }
    }

    pthread_exit(NULL);
}


// Main test function
int main(int argc, char *argv[]) {
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

    int N_values[] = {0, 10, 100, 200, 300, 400, 500};
    int thread_counts[] = {1, 2, 4, 8};
    int N_tests = sizeof(N_values) / sizeof(N_values[0]);
    int T_tests = sizeof(thread_counts) / sizeof(thread_counts[0]);
    char filename[PATH_MAX];
    char password[MAX_PASSW_LEN + 1];
    char *read_dir = "./refmon_test/read";
    char *write_dir = "./refmon_test/write";
    char *create_dir = "./refmon_test/create";
    char *protected_dir = "./refmon_test/protected";
    char *results_dir = "./refmon_test/results";
    struct stat st = {0};
    int N, i, n_idx, t_idx, k;

    uint64_t read_time, write_time, create_time;
    uint64_t total_read_time, total_write_time, total_create_time;
    int valid_read_count, valid_write_count, valid_create_count;

    uint64_t read_times[N_tests];
    uint64_t write_times[N_tests];
    uint64_t create_times[N_tests];
    memset(read_times, 0, sizeof(read_times));
    memset(write_times, 0, sizeof(write_times));
    memset(create_times, 0, sizeof(create_times));

    FILE *csv_file;

    // Read password from 'the_secret' file
    FILE *pass_file = fopen("the_secret", "r");
    if (!pass_file) {
        perror("fopen the_secret");
        exit(EXIT_FAILURE);
    }
    if (!fgets(password, sizeof(password), pass_file)) {
        perror("fgets");
        fclose(pass_file);
        exit(EXIT_FAILURE);
    }
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n')
        password[len - 1] = '\0';
    fclose(pass_file);

    // Prepare directories
    if (stat(read_dir, &st) == -1 && mkdir(read_dir, 0666) != 0) {
        perror("mkdir read_dir");
        exit(EXIT_FAILURE);
    }
    if (stat(write_dir, &st) == -1 && mkdir(write_dir, 0666) != 0) {
        perror("mkdir write_dir");
        exit(EXIT_FAILURE);
    }
    if (stat(create_dir, &st) == -1 && mkdir(create_dir, 0666) != 0) {
        perror("mkdir create_dir");
        exit(EXIT_FAILURE);
    }
    if (stat(protected_dir, &st) == -1 && mkdir(protected_dir, 0666) != 0) {
        perror("mkdir protected_dir");
        exit(EXIT_FAILURE);
    }
    if (stat(results_dir, &st) == -1 && mkdir(results_dir, 0666) != 0) {
        perror("mkdir results_dir");
        exit(EXIT_FAILURE);
    }

    // Open CSV file for results
    snprintf(filename, sizeof(filename), "%s/results.csv", results_dir);
    csv_file = fopen(filename, "w");
    if (!csv_file) {
        perror("fopen results.csv");
        exit(EXIT_FAILURE);
    }
    fprintf(csv_file, "N,Threads,Read Time (cycles),Write Time (cycles),Create Time (cycles)\n");

    // Main test loop
    invoke_refmon_manage(REFMON_SET_REC_ON);
    for (n_idx = 0; n_idx < N_tests; n_idx++) {
        N = N_values[n_idx];
        if (verbose) printf("\nTesting with N = %d protected files\n", N);

        if (N > 0)
        {
            for (i = 0; i < N; i++)
            {
                snprintf(filename, sizeof(filename), "%s/protected_file_%d", protected_dir, i);
                create_file(filename);
                if (verbose) printf("Protecting file: %s\n", filename);
                if (invoke_refmon_reconfigure(REFMON_ACTION_PROTECT, password, filename, PATH_TTL) < 0)
                {
                    fprintf(stderr, "Failed to protect file: %s\n", filename);
                }
            }
        }
        for (t_idx = 0; t_idx < T_tests; t_idx++) {
            int num_threads = thread_counts[t_idx];
            pthread_t threads[num_threads];
            thread_data_t thread_data_array[num_threads];

            // Create threads
            for (i = 0; i < num_threads; i++) {
                thread_data_array[i].thread_id = i;
                thread_data_array[i].n_runs = N_RUNS; // Each thread performs all N_RUNS
                thread_data_array[i].m_files = M;
                strncpy(thread_data_array[i].read_dir, read_dir, PATH_MAX);
                strncpy(thread_data_array[i].write_dir, write_dir, PATH_MAX);
                strncpy(thread_data_array[i].create_dir, create_dir, PATH_MAX);

                // Initialize per-thread accumulators
                thread_data_array[i].total_read_time = 0;
                thread_data_array[i].total_write_time = 0;
                thread_data_array[i].total_create_time = 0;
                thread_data_array[i].valid_read_count = 0;
                thread_data_array[i].valid_write_count = 0;
                thread_data_array[i].valid_create_count = 0;

                int rc = pthread_create(&threads[i], NULL, thread_test_function, (void*)&thread_data_array[i]);
                if (rc) {
                    fprintf(stderr, "Error: Unable to create thread %d, rc = %d\n", i, rc);
                    exit(EXIT_FAILURE);
                }
            }

            // Wait for threads to finish
            for (i = 0; i < num_threads; i++) {
                pthread_join(threads[i], NULL);
            }

            // Aggregate results from all threads
            uint64_t total_read_time = 0;
            uint64_t total_write_time = 0;
            uint64_t total_create_time = 0;
            int valid_read_count = 0;
            int valid_write_count = 0;
            int valid_create_count = 0;

            for (i = 0; i < num_threads; i++) {
                total_read_time += thread_data_array[i].total_read_time;
                total_write_time += thread_data_array[i].total_write_time;
                total_create_time += thread_data_array[i].total_create_time;
                valid_read_count += thread_data_array[i].valid_read_count;
                valid_write_count += thread_data_array[i].valid_write_count;
                valid_create_count += thread_data_array[i].valid_create_count;
            }

            // Compute averages
            uint64_t average_read_time = valid_read_count > 0 ? total_read_time / valid_read_count : 0;
            uint64_t average_write_time = valid_write_count > 0 ? total_write_time / valid_write_count : 0;
            uint64_t average_create_time = valid_create_count > 0 ? total_create_time / valid_create_count : 0;

            // Output results
            if (verbose) {
                printf("N = %d, Threads = %d: Average Read Time = %lu cycles, Average Write Time = %lu cycles, Average Create Time = %lu cycles\n",
                       N, num_threads, average_read_time, average_write_time, average_create_time);
            }

            // Write to CSV
            fprintf(csv_file, "%d,%d,%lu,%lu,%lu\n", N, num_threads, average_read_time, average_write_time, average_create_time);
        }

        // Unprotect files if N > 0
        if (N > 0) {
            for (i = 0; i < N; i++) {
                snprintf(filename, sizeof(filename), "%s/protected_file_%d", protected_dir, i);
                if (verbose) printf("Unprotecting file: %s\n", filename);
                if (invoke_refmon_reconfigure(REFMON_ACTION_UNPROTECT, password, filename, PATH_TTL) < 0) {
                    fprintf(stderr, "Failed to unprotect file: %s\n", filename);
                }
                remove(filename);
            }
        }
    }

    fclose(csv_file);

    // Cleanup
    cleanup_directory(read_dir);
    cleanup_directory(write_dir);
    cleanup_directory(create_dir);
    cleanup_directory(protected_dir);
    invoke_refmon_manage(REFMON_SET_OFF);

    if (verbose) printf("\nResults saved to %s/results.csv\n", results_dir);
    return 0;
}
