
#define _XOPEN_SOURCE 700

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/evp.h>

#define HASH_SIZE 32
#define BUFFER_SIZE 8192
#define MAX_FILES 10000

typedef struct {
    char path[PATH_MAX];
    off_t size;
    unsigned char hash[HASH_SIZE];
    int hash_ok;
} FileInfo;

static FileInfo files[MAX_FILES];
static int file_count = 0;
static int hash_failures = 0;

/* Add a regular file to the file list. */
static int add_file(const char *path, off_t size)
{
    if (file_count >= MAX_FILES) {
        fprintf(stderr, "File limit reached: %d\n", MAX_FILES);
        return -1;
    }

    if (strlen(path) >= sizeof(files[0].path)) {
        fprintf(stderr, "Path too long: %s\n", path);
        return -1;
    }

    snprintf(files[file_count].path,
             sizeof(files[file_count].path), "%s", path);

    files[file_count].size = size;
    files[file_count].hash_ok = 0;
    memset(files[file_count].hash, 0, HASH_SIZE);

    file_count++;
    return 0;
}

/* Recursively scan a directory without following symbolic links. */
static int scan_directory(const char *path)
{
    DIR *dir = opendir(path);

    if (dir == NULL) {
        perror(path);
        return -1;
    }

    struct dirent *entry;
    int result = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char full_path[PATH_MAX];

        int n = snprintf(full_path, sizeof(full_path),
                         "%s/%s", path, entry->d_name);

        if (n < 0 || (size_t)n >= sizeof(full_path)) {
            fprintf(stderr, "Path too long inside: %s\n", path);
            result = -1;
            continue;
        }

        struct stat st;

        if (lstat(full_path, &st) != 0) {
            perror(full_path);
            result = -1;
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (scan_directory(full_path) != 0)
                result = -1;
        } else if (S_ISREG(st.st_mode)) {
            if (add_file(full_path, st.st_size) != 0)
                result = -1;
        }
    }

    if (closedir(dir) != 0) {
        perror("closedir");
        result = -1;
    }

    return result;
}

/* Calculate the SHA-256 hash of a file using read() and OpenSSL EVP. */
static int calculate_hash(FileInfo *file)
{
    int fd = open(file->path, O_RDONLY);

    if (fd < 0) {
        perror(file->path);
        return -1;
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL) {
        fprintf(stderr, "Unable to allocate SHA-256 context\n");
        close(fd);
        return -1;
    }

    int ok = 0;
    unsigned char buffer[BUFFER_SIZE];
    unsigned int digest_length = 0;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        goto cleanup;

    for (;;) {
        ssize_t bytes_read = read(fd, buffer, sizeof(buffer));

        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;

            perror(file->path);
            goto cleanup;
        }

        if (bytes_read == 0)
            break;

        if (EVP_DigestUpdate(ctx, buffer,
                             (size_t)bytes_read) != 1) {
            fprintf(stderr, "Hash update failed: %s\n",
                    file->path);
            goto cleanup;
        }
    }

    if (EVP_DigestFinal_ex(ctx, file->hash,
                           &digest_length) != 1 ||
        digest_length != HASH_SIZE) {
        fprintf(stderr, "Hash finalization failed: %s\n",
                file->path);
        goto cleanup;
    }

    file->hash_ok = 1;
    ok = 1;

cleanup:
    EVP_MD_CTX_free(ctx);

    if (close(fd) != 0) {
        perror(file->path);
        ok = 0;
        file->hash_ok = 0;
    }

    return ok ? 0 : -1;
}

/* Return true when two successfully hashed files match. */
static int same_content(int i, int j)
{
    if (!files[i].hash_ok || !files[j].hash_ok)
        return 0;

    if (files[i].size != files[j].size)
        return 0;

    return memcmp(files[i].hash, files[j].hash,
                  HASH_SIZE) == 0;
}

/* Print a full SHA-256 hash. */
static void print_hash(const unsigned char *hash)
{
    for (int i = 0; i < HASH_SIZE; i++)
        printf("%02x", hash[i]);
}

/* Display duplicate groups and calculate potential savings. */
static void display_duplicates(void)
{
    int group_number = 0;
    int extra_copies = 0;
    long long recoverable_bytes = 0;

    for (int i = 0; i < file_count; i++) {
        if (!files[i].hash_ok)
            continue;

        int already_seen = 0;

        for (int j = 0; j < i; j++) {
            if (same_content(i, j)) {
                already_seen = 1;
                break;
            }
        }

        if (already_seen)
            continue;

        int count = 0;

        for (int j = i; j < file_count; j++) {
            if (same_content(i, j))
                count++;
        }

        if (count < 2)
            continue;

        group_number++;

        printf("\nDuplicate Group %d\n", group_number);
        printf("Size: %lld bytes\n",
               (long long)files[i].size);

        for (int j = i; j < file_count; j++) {
            if (same_content(i, j))
                printf("  %s\n", files[j].path);
        }

        printf("SHA-256: ");
        print_hash(files[i].hash);
        printf("\n");

        extra_copies += count - 1;

        recoverable_bytes +=
            (long long)(count - 1) * (long long)files[i].size;
    }

    printf("\n========== SUMMARY ==========\n");
    printf("Files discovered: %d\n", file_count);
    printf("Hash failures: %d\n", hash_failures);
    printf("Duplicate groups: %d\n", group_number);
    printf("Extra duplicate copies: %d\n", extra_copies);
    printf("Potential recoverable space: %lld bytes\n",
           recoverable_bytes);
}

/* Write a CSV field safely, including commas and quotation marks. */
static void csv_field(FILE *out, const char *value)
{
    fputc('"', out);

    while (*value != '\0') {
        if (*value == '"')
            fputc('"', out);

        fputc(*value, out);
        value++;
    }

    fputc('"', out);
}

/* Export every member of every duplicate group to CSV. */
static int export_csv(void)
{
    FILE *out = fopen("dedup_report.csv", "w");

    if (out == NULL) {
        perror("Cannot create CSV report");
        return -1;
    }

    if (fprintf(out, "Group,File Path,Size Bytes,SHA256\n") < 0) {
        perror("Writing CSV header");
        fclose(out);
        return -1;
    }

    int group_number = 0;

    for (int i = 0; i < file_count; i++) {
        if (!files[i].hash_ok)
            continue;

        /* Skip this file if an earlier file represents its group. */
        int already_seen = 0;

        for (int j = 0; j < i; j++) {
            if (same_content(i, j)) {
                already_seen = 1;
                break;
            }
        }

        if (already_seen)
            continue;

        int count = 0;

        for (int j = 0; j < file_count; j++) {
            if (same_content(i, j))
                count++;
        }

        if (count < 2)
            continue;

        group_number++;

        for (int j = 0; j < file_count; j++) {
            if (!same_content(i, j))
                continue;

            if (fprintf(out, "%d,", group_number) < 0) {
                fclose(out);
                return -1;
            }

            csv_field(out, files[j].path);

            if (fprintf(out, ",%lld,",
                        (long long)files[j].size) < 0) {
                fclose(out);
                return -1;
            }

            for (int k = 0; k < HASH_SIZE; k++) {
                if (fprintf(out, "%02x", files[j].hash[k]) < 0) {
                    fclose(out);
                    return -1;
                }
            }

            if (fputc('\n', out) == EOF) {
                fclose(out);
                return -1;
            }
        }
    }

    if (fclose(out) != 0) {
        perror("Error closing CSV report");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        return 1;
    }

    struct stat root;

    if (stat(argv[1], &root) != 0 ||
        !S_ISDIR(root.st_mode)) {
        fprintf(stderr, "Error: provide a valid directory.\n");
        return 1;
    }

    printf("Scanning directory: %s\n", argv[1]);

    if (scan_directory(argv[1]) != 0)
        fprintf(stderr, "Warning: some directory entries could not be scanned.\n");

    printf("Files discovered: %d\n", file_count);
    printf("Calculating SHA-256 hashes...\n");

    for (int i = 0; i < file_count; i++) {
        if (calculate_hash(&files[i]) != 0)
            hash_failures++;
    }

    display_duplicates();

    if (export_csv() == 0)
        printf("CSV report: dedup_report.csv\nReport exported successfully.\n");
    else
        fprintf(stderr, "CSV report export failed.\n");

    printf("No files were deleted or intentionally modified.\n");

    return 0;
}
