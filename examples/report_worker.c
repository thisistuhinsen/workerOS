/* A libc-only worker. No Python, socket transport, file-path open, or authority. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static const char report[] = "ready\n";

static void fail(int code, const char *reason) {
    fprintf(stderr, "report-worker: %s\n", reason);
    exit(code);
}

static const char *required(const char *key) {
    const char *v = getenv(key);
    if (!v || !*v) fail(2, "missing ABI input");
    return v;
}

static uintmax_t number(const char *key) {
    const char *v = required(key);
    char *end;
    uintmax_t n;
    for (const char *s = v; *s; ++s)
        if (*s < '0' || *s > '9') fail(2, "invalid decimal ABI input");
    errno = 0;
    n = strtoumax(v, &end, 10);
    if (errno || *end) fail(2, "out-of-range ABI input");
    return n;
}

static void before(uintmax_t deadline) {
    struct timespec t;
    if (!deadline || deadline > INT64_MAX || clock_gettime(CLOCK_MONOTONIC, &t) != 0)
        fail(2, "invalid monotonic clock");
    if ((uintmax_t)t.tv_sec * UINTMAX_C(1000000000) + (uintmax_t)t.tv_nsec >= deadline)
        fail(4, "expired original");
}

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "local-report") != 0 ||
        strcmp(required("WORKER_HANDOFF_ABI"), "1") != 0)
        fail(2, "expected local-report on ABI 1");
    const char *role = required("WORKER_HANDOFF_ROLE");
    const char *name = required("WORKER_HANDOFF_NAME");
    const char *access = required("WORKER_HANDOFF_ACCESS_REPORT");
    const uintmax_t deadline = number("WORKER_HANDOFF_DEADLINE_NS");
    const uintmax_t nfd = number("WORKER_HANDOFF_FD_REPORT");
    const uintmax_t dev = number("WORKER_HANDOFF_DEV_REPORT");
    const uintmax_t ino = number("WORKER_HANDOFF_INO_REPORT");
    if (nfd < 3 || nfd > INT_MAX) fail(2, "invalid original slot");
    const int fd = (int)nfd;
    before(deadline);
    struct stat st;
    const int flags = fcntl(fd, F_GETFL);
    const int descriptor_flags = fcntl(fd, F_GETFD);
    if (flags < 0 || descriptor_flags < 0 || flags & O_PATH ||
        fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (uintmax_t)st.st_dev != dev || (uintmax_t)st.st_ino != ino ||
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0)
        fail(3, "not the declared original");
    const int mode = flags & O_ACCMODE;
    if (strcmp(role, "write") == 0) {
        if (mode != O_WRONLY || strcmp(access, "write") ||
            st.st_uid != getuid() || st.st_size != 0)
            fail(3, "not a newly empty caller-owned writable file");
        size_t at = 0;
        while (at < sizeof report - 1) {
            before(deadline);
            ssize_t put = write(fd, report + at, sizeof report - 1 - at);
            if (put < 0 && errno == EINTR) continue;
            if (put <= 0) fail(5, "write failed, partial effect possible");
            at += (size_t)put;
        }
        if (fsync(fd) != 0) fail(5, "fsync failed, durability unknown");
    } else {
        if (mode != O_RDONLY || strcmp(access, "read") ||
            st.st_size != (off_t)(sizeof report - 1))
            fail(3, "not the exact expected read-only report");
        if (strcmp(role, "read") == 0) {
            char actual[sizeof report - 1];
            size_t at = 0;
            while (at < sizeof actual) {
                before(deadline);
                ssize_t got = pread(fd, actual + at, sizeof actual - at, (off_t)at);
                if (got < 0 && errno == EINTR) continue;
                if (got <= 0) fail(5, "incomplete original");
                at += (size_t)got;
            }
            char beyond;
            if (memcmp(actual, report, sizeof actual) != 0 ||
                pread(fd, &beyond, 1, (off_t)sizeof actual) != 0)
                fail(5, "unexpected data or EOF");
        } else if (strcmp(role, "observe") != 0) {
            fail(2, "unknown example application role");
        }
    }
    before(deadline);
    if (close(fd) != 0) fail(5, "local close failed");
    errno = 0;
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) fail(5, "local slot still accessible");
    before(deadline);
    printf("%s %s LOCAL_OK\n", name, role);
    return 0;
}
