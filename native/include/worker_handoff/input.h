#ifndef WORKER_HANDOFF_INPUT_H
#define WORKER_HANDOFF_INPUT_H

#if !defined(__linux__)
#error "worker-handoff inherited descriptors require Linux"
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef enum worker_handoff_ownership {
    WORKER_HANDOFF_BORROWED,
    WORKER_HANDOFF_OWNED
} worker_handoff_ownership;

typedef struct worker_handoff_input {
    int fd;
    uintmax_t device;
    uintmax_t inode;
    int access_mode;
    worker_handoff_ownership ownership;
} worker_handoff_input;

#define WORKER_HANDOFF_INPUT_INIT { -1, 0, 0, 0, WORKER_HANDOFF_BORROWED }

static inline int worker_handoff_detail_error(int code)
{
    errno = code;
    return -1;
}

static inline int worker_handoff_detail_binding(const char *name)
{
    if (name == NULL || *name < 'A' || *name > 'Z') {
        return 0;
    }
    for (++name; *name != '\0'; ++name) {
        if ((*name < 'A' || *name > 'Z') && (*name < '0' || *name > '9') && *name != '_') {
            return 0;
        }
    }
    return 1;
}

static inline int worker_handoff_detail_uint(const char *value, uintmax_t *result)
{
    uintmax_t number = 0;
    if (value == NULL || *value == '\0' || (*value == '0' && value[1] != '\0')) {
        return 0;
    }
    for (; *value != '\0'; ++value) {
        if (*value < '0' || *value > '9') {
            return 0;
        }
        unsigned int digit = (unsigned int)(*value - '0');
        if (number > (UINTMAX_MAX - digit) / 10) {
            return 0;
        }
        number = number * 10 + digit;
    }
    *result = number;
    return 1;
}

static inline const char *worker_handoff_detail_env(char *key, const char *prefix, const char *binding)
{
    strcpy(key, prefix);
    strcat(key, binding);
    return getenv(key);
}

static inline ssize_t worker_handoff_detail_pread(int fd, void *buffer, size_t count, off_t offset)
{
    ssize_t result;
    do {
        result = pread(fd, buffer, count, offset);
    } while (result == -1 && errno == EINTR);
    return result;
}

static inline int worker_handoff_detail_check(const worker_handoff_input *input)
{
    struct stat actual;
    if (fstat(input->fd, &actual) == -1) {
        return -1;
    }
    if (!S_ISREG(actual.st_mode)) {
        return worker_handoff_detail_error(EINVAL);
    }
    if ((uintmax_t)actual.st_dev != input->device || (uintmax_t)actual.st_ino != input->inode) {
        return worker_handoff_detail_error(ESTALE);
    }
    int flags = fcntl(input->fd, F_GETFL);
    if (flags == -1) {
        return -1;
    }
    if ((flags & O_ACCMODE) != input->access_mode) {
        return worker_handoff_detail_error(EACCES);
    }
#ifdef O_PATH
    if ((flags & O_PATH) != 0) {
        return worker_handoff_detail_error(EACCES);
    }
#else
    /* Strict POSIX headers may hide O_PATH, whose value varies by architecture.
     * Linux rejects positional I/O on O_PATH descriptors even for zero bytes. */
    char ignored;
    if (worker_handoff_detail_pread(input->fd, &ignored, 0, 0) == -1) {
        return -1;
    }
#endif
    return 0;
}

/* Validate a named ABI-v1 binding and adopt it into an initialized empty handle.
 * On failure the descriptor remains with its current owner. */
static inline int worker_handoff_open_inherited(const char *binding,
                                                 worker_handoff_ownership ownership,
                                                 worker_handoff_input *input)
{
    const char *abi = getenv("WORKER_HANDOFF_ABI");
    if (input == NULL || !worker_handoff_detail_binding(binding)
        || (ownership != WORKER_HANDOFF_BORROWED && ownership != WORKER_HANDOFF_OWNED)
        || abi == NULL || strcmp(abi, "1") != 0) {
        return worker_handoff_detail_error(EINVAL);
    }
    if (input->fd >= 0) {
        return worker_handoff_detail_error(EBUSY);
    }

    const size_t prefix_size = sizeof("WORKER_HANDOFF_ACCESS_");
    const size_t binding_length = strlen(binding);
    if (binding_length > SIZE_MAX - prefix_size) {
        return worker_handoff_detail_error(EOVERFLOW);
    }
    char *key = (char *)malloc(prefix_size + binding_length);
    if (key == NULL) {
        return -1;
    }

    uintmax_t fd;
    worker_handoff_input candidate = WORKER_HANDOFF_INPUT_INIT;
    int valid =
        worker_handoff_detail_uint(worker_handoff_detail_env(key, "WORKER_HANDOFF_FD_", binding), &fd)
        && fd >= 3 && fd <= INT_MAX
        && worker_handoff_detail_uint(worker_handoff_detail_env(key, "WORKER_HANDOFF_DEV_", binding), &candidate.device)
        && worker_handoff_detail_uint(worker_handoff_detail_env(key, "WORKER_HANDOFF_INO_", binding), &candidate.inode)
        && candidate.inode > 0;
    if (valid) {
        const char *access = worker_handoff_detail_env(key, "WORKER_HANDOFF_ACCESS_", binding);
        if (access != NULL && strcmp(access, "read") == 0) {
            candidate.access_mode = O_RDONLY;
        } else if (access != NULL && strcmp(access, "read-write") == 0) {
            candidate.access_mode = O_RDWR;
        } else {
            valid = 0;
        }
    }
    free(key);
    if (!valid) {
        return worker_handoff_detail_error(EINVAL);
    }

    candidate.fd = (int)fd;
    candidate.ownership = ownership;
    if (worker_handoff_detail_check(&candidate) == -1) {
        return -1;
    }
    *input = candidate;
    return 0;
}

/* Return bytes read, zero at EOF or -1 with errno. The shared offset is unchanged. */
static inline ssize_t worker_handoff_read_at(const worker_handoff_input *input,
                                              void *buffer, size_t count, off_t offset)
{
    if (input == NULL || input->fd < 0) {
        return worker_handoff_detail_error(EBADF);
    }
    if ((buffer == NULL && count != 0) || count > (size_t)SSIZE_MAX || offset < 0) {
        return worker_handoff_detail_error(EINVAL);
    }
    if (worker_handoff_detail_check(input) == -1) {
        return -1;
    }

    return worker_handoff_detail_pread(input->fd, buffer, count, offset);
}

/* Invalidate the handle. Only owned descriptors are closed, once. */
static inline int worker_handoff_close(worker_handoff_input *input)
{
    if (input == NULL) {
        return worker_handoff_detail_error(EINVAL);
    }
    worker_handoff_input prior = *input;
    worker_handoff_input empty = WORKER_HANDOFF_INPUT_INIT;
    *input = empty;
    if (prior.fd < 0 || prior.ownership == WORKER_HANDOFF_BORROWED) {
        return 0;
    }
    if (worker_handoff_detail_check(&prior) == -1) {
        return -1;
    }
    return close(prior.fd);
}

#endif
