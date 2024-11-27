/*
 * @file baseline_test.c
 *
 * @brief A minimal test to compute baseline overhead
 *        for file operations (read, write, create) without RefMon module involvement.
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

#define PATH_MAX 4096
#define N_RUNS 1000 // Number of test runs for averaging

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
        char filepath[512];
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

// Main test function
int main() {
    char test_dir[PATH_MAX] = "./refmon_test/tests";
    char results_dir[PATH_MAX] = "./refmon_test/results";
    char test_file[PATH_MAX];
    char baseline_csv[PATH_MAX];
    uint64_t read_time, write_time, create_time;
    uint64_t total_read_time = 0, total_write_time = 0, total_create_time = 0;
    int valid_read_count = 0, valid_write_count = 0, valid_create_count = 0;

    struct stat st;

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

    // Create test file path
    if (snprintf(test_file, sizeof(test_file), "%s/baseline_test_file", test_dir) >= sizeof(test_file)) {
        fprintf(stderr, "Path truncation occurred for test_file\n");
        return EXIT_FAILURE;
    }

    // Create a test file
    if (create_file(test_file) < 0) {
        fprintf(stderr, "Failed to create test file\n");
        return EXIT_FAILURE;
    }

    // Perform multiple runs to gather average read, write, and create times
    for (int i = 0; i < N_RUNS; i++) {
        // Measure read time
        read_time = single_open_read(test_file);
        if (read_time != (uint64_t)-1) {
            total_read_time += read_time;
            valid_read_count++;
        }

        // Measure write time
        write_time = single_open_write(test_file);
        if (write_time != (uint64_t)-1) {
            total_write_time += write_time;
            valid_write_count++;
        }

        // Measure file creation time
        create_time = single_file_create(test_file, i);
        if (create_time != (uint64_t)-1) {
            total_create_time += create_time;
            valid_create_count++;
        }
    }

    // Calculate averages
    uint64_t average_read_time = valid_read_count > 0 ? total_read_time / valid_read_count : 0;
    uint64_t average_write_time = valid_write_count > 0 ? total_write_time / valid_write_count : 0;
    uint64_t average_create_time = valid_create_count > 0 ? total_create_time / valid_create_count : 0;

    // Prepare CSV file path
    if (snprintf(baseline_csv, sizeof(baseline_csv), "%s/baseline.csv", results_dir) >= sizeof(baseline_csv)) {
        fprintf(stderr, "Path truncation occurred for baseline_csv\n");
        return EXIT_FAILURE;
    }

    // Save results to baseline.csv
    FILE *csv_file = fopen(baseline_csv, "w");
    if (!csv_file) {
        perror("fopen baseline.csv");
        return EXIT_FAILURE;
    }
    fprintf(csv_file, "Read Time (cycles),Write Time (cycles),Create Time (cycles)\n");
    fprintf(csv_file, "%lu,%lu,%lu\n", average_read_time, average_write_time, average_create_time);
    fclose(csv_file);

    // Clean up
    remove(test_file);
    cleanup_directory(test_dir);
    printf("Baseline results saved to %s\n", baseline_csv);

    return EXIT_SUCCESS;
}
