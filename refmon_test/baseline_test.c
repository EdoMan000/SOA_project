/*
 * @file baseline_test.c
 *
 * @brief A minimal test to compute baseline overhead
 *        for file operations (read, write, create) without RefMon module involvement,
 *        using threads to perform concurrent operations.
 *
 * @author
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
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdint.h> // For uint64_t
#include <pthread.h>

#define PATH_MAX 4096
#define N_RUNS 1000 // Number of test runs per thread
#define M 1         // Number of test files per thread

typedef struct {
    int thread_id;
    int n_runs;
    int m_files;
    char test_dir[PATH_MAX];
    uint64_t total_read_time;
    uint64_t total_write_time;
    uint64_t total_create_time;
    int valid_read_count;
    int valid_write_count;
    int valid_create_count;
} thread_data_t;

// Function to read TSC (Time Stamp Counter)
static inline uint64_t rdtsc() {
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

// Function to create a file with some content
int create_file(const char *filename) {
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

// Function to measure creation of a new file
uint64_t single_file_create(const char *filename, int iteration) {
    char new_file[PATH_MAX];
    snprintf(new_file, sizeof(new_file), "%s_%d", filename, iteration);

    uint64_t start_cycles, end_cycles;

    start_cycles = rdtsc();
    int fd = open(new_file, O_CREAT | O_WRONLY, 0666);
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
    DIR *dir = opendir(dirpath);
    if (dir) {
        struct dirent *entry;
        char filepath[PATH_MAX];
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;
            snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);
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

            int ret = snprintf(filename, sizeof(filename), "%s/test_file_%d_thread_%d", data->test_dir, i, data->thread_id);
            if (ret >= sizeof(filename)) {
                fprintf(stderr, "Error: filename too long, truncated.\n");
                pthread_exit(NULL);
            }

            // Measure read time
            uint64_t read_time = single_open_read(filename);
            if (read_time != (uint64_t)-1) {
                data->total_read_time += read_time;
                data->valid_read_count++;
            }

            // Measure write time
            uint64_t write_time = single_open_write(filename);
            if (write_time != (uint64_t)-1) {
                data->total_write_time += write_time;
                data->valid_write_count++;
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

int main() {
    char test_dir[PATH_MAX] = "./refmon_test/tests";
    char results_dir[PATH_MAX] = "./refmon_test/results";
    char baseline_csv[PATH_MAX];
    struct stat st;

    int thread_counts[] = {1, 2, 4, 8};
    int T_tests = sizeof(thread_counts) / sizeof(thread_counts[0]);

    // Ensure the test directory exists
    if (stat(test_dir, &st) == -1) {
        if (mkdir(test_dir, 0666) != 0) {
            perror("mkdir test_dir");
            return EXIT_FAILURE;
        }
    }

    // Ensure the results directory exists
    if (stat(results_dir, &st) == -1) {
        if (mkdir(results_dir, 0666) != 0) {
            perror("mkdir results_dir");
            return EXIT_FAILURE;
        }
    }

    // Prepare CSV file path
    if (snprintf(baseline_csv, sizeof(baseline_csv), "%s/baseline.csv", results_dir) >= sizeof(baseline_csv)) {
        fprintf(stderr, "Path truncation occurred for baseline_csv\n");
        return EXIT_FAILURE;
    }

    // Open CSV file for results
    FILE *csv_file = fopen(baseline_csv, "w");
    if (!csv_file) {
        perror("fopen baseline.csv");
        return EXIT_FAILURE;
    }
    fprintf(csv_file, "Threads,Read Time (cycles),Write Time (cycles),Create Time (cycles)\n");

    // Main test loop over thread counts
    for (int t_idx = 0; t_idx < T_tests; t_idx++) {
        int num_threads = thread_counts[t_idx];
        pthread_t threads[num_threads];
        thread_data_t thread_data_array[num_threads];
        char filename[PATH_MAX];

        // Create test files for this thread count
        for (int i = 0; i < num_threads; i++) {
            for (int k = 0; k < M; k++) {
                int ret = snprintf(filename, sizeof(filename), "%s/test_file_%d_thread_%d", test_dir, k, i);
                if (ret >= sizeof(filename)) {
                    fprintf(stderr, "Error: filename too long, truncated.\n");
                    exit(EXIT_FAILURE);
                }
                create_file(filename);
            }
        }

        // Create threads
        for (int i = 0; i < num_threads; i++) {
            thread_data_array[i].thread_id = i;
            thread_data_array[i].n_runs = N_RUNS;
            thread_data_array[i].m_files = M;
            strncpy(thread_data_array[i].test_dir, test_dir, PATH_MAX);

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
        for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
        }

        // Aggregate results from all threads
        uint64_t total_read_time = 0;
        uint64_t total_write_time = 0;
        uint64_t total_create_time = 0;
        int valid_read_count = 0;
        int valid_write_count = 0;
        int valid_create_count = 0;

        for (int i = 0; i < num_threads; i++) {
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
        //printf("Threads = %d: Average Read Time = %lu cycles, Average Write Time = %lu cycles, Average Create Time = %lu cycles\n", num_threads, average_read_time, average_write_time, average_create_time);

        // Write to CSV
        fprintf(csv_file, "%d,%lu,%lu,%lu\n", num_threads, average_read_time, average_write_time, average_create_time);

        // Clean up test files for this thread count
        for (int i = 0; i < num_threads; i++) {
            for (int k = 0; k < M; k++) {
                int ret = snprintf(filename, sizeof(filename), "%s/test_file_%d_thread_%d", test_dir, k, i);
                if (ret >= sizeof(filename)) {
                    fprintf(stderr, "Error: filename too long, truncated.\n");
                    exit(EXIT_FAILURE);
                }
                remove(filename);
            }
        }
    }

    fclose(csv_file);

    // Clean up directories
    cleanup_directory(test_dir);

    //printf("Baseline results saved to %s\n", baseline_csv);

    return EXIT_SUCCESS;
}
