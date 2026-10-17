
#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <errno.h>
#include <limits.h>

#define MAX_FILES 10000
#define HASH_SIZE SHA256_DIGEST_LENGTH

typedef struct {
    char path[PATH_MAX];
    off_t size;
    unsigned char hash[HASH_SIZE];
    int hashed;
} FileInfo;

static FileInfo files[MAX_FILES];
static int file_count = 0;

static int hash_file(const char *path, unsigned char *out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    unsigned char buffer[8192];
    ssize_t n;

    while ((n = read(fd, buffer, sizeof(buffer))) > 0)
        SHA256_Update(&ctx, buffer, (size_t)n);

    int saved_errno = errno;
    int read_failed = (n < 0);
    if (close(fd) < 0) read_failed = 1;
    errno = saved_errno;

    if (read_failed) return -1;

    SHA256_Final(out, &ctx);
    return 0;
}

static void scan_directory(const char *dirpath) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        perror(dirpath);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") ||
            !strcmp(entry->d_name, ".."))
            continue;

        char path[PATH_MAX];
        int len = snprintf(path, sizeof(path), "%s/%s",
                           dirpath, entry->d_name);
        if (len < 0 || (size_t)len >= sizeof(path)) continue;

        struct stat st;
        if (lstat(path, &st) < 0) continue;

        /* Do not follow symbolic links. */
        if (S_ISDIR(st.st_mode)) {
            scan_directory(path);
        } else if (S_ISREG(st.st_mode)) {
            if (file_count >= MAX_FILES) {
                fprintf(stderr, "File limit reached.\n");
                break;
            }

            strncpy(files[file_count].path, path, PATH_MAX - 1);
            files[file_count].path[PATH_MAX - 1] = '\0';
            files[file_count].size = st.st_size;
            files[file_count].hashed = 0;
            file_count++;
        }
    }

    closedir(dir);
}

static void print_hash(const unsigned char *hash) {
    for (int i = 0; i < HASH_SIZE; i++)
        printf("%02x", hash[i]);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
        return 1;
    }

    struct stat root;
    if (stat(argv[1], &root) < 0 || !S_ISDIR(root.st_mode)) {
        fprintf(stderr, "Please provide a valid directory.\n");
        return 1;
    }

    scan_directory(argv[1]);

    printf("\nFiles scanned: %d\n", file_count);
    printf("Searching for duplicate contents...\n\n");

    long long duplicate_bytes = 0;
    int groups = 0;

    for (int i = 0; i < file_count; i++) {
        if (files[i].hashed) continue;

        int candidates = 0;
        for (int j = i + 1; j < file_count; j++) {
            if (files[j].size == files[i].size)
                candidates++;
        }

        if (candidates == 0) continue;

        if (hash_file(files[i].path, files[i].hash) < 0) {
            fprintf(stderr, "Cannot read: %s\n", files[i].path);
            files[i].hashed = 1;
            continue;
        }
        files[i].hashed = 1;

        int members[MAX_FILES];
        int count = 1;
        members[0] = i;

        for (int j = i + 1; j < file_count; j++) {
            if (files[j].hashed || files[j].size != files[i].size)
                continue;

            if (hash_file(files[j].path, files[j].hash) < 0) {
                fprintf(stderr, "Cannot read: %s\n", files[j].path);
                files[j].hashed = 1;
                continue;
            }
            files[j].hashed = 1;

            if (memcmp(files[i].hash, files[j].hash, HASH_SIZE) == 0)
                members[count++] = j;
        }

        if (count > 1) {
            groups++;
            printf("Duplicate group %d (size: %lld bytes)\n",
                   groups, (long long)files[i].size);

            for (int k = 0; k < count; k++)
                printf("  %s\n", files[members[k]].path);

            printf("  SHA-256: ");
            print_hash(files[i].hash);
            printf("\n\n");

            duplicate_bytes += (long long)(count - 1) * files[i].size;
        }
    }

    printf("Duplicate groups: %d\n", groups);
    printf("Potential recoverable space: %lld bytes\n", duplicate_bytes);
    printf("No files were modified or deleted.\n");

    return 0;
}
