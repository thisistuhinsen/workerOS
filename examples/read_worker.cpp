#define _POSIX_C_SOURCE 200809L
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

int main() {
    const char* abi = std::getenv("WORKER_HANDOFF_ABI");
    const char* value = std::getenv("WORKER_HANDOFF_FD_INPUT");
    if (!abi || std::strcmp(abi, "1") || !value || *value < '1' || *value > '9')
        return 2;
    for (const char* digit = value; *digit; ++digit)
        if (*digit < '0' || *digit > '9') return 2;

    char* end;
    errno = 0;
    long number = std::strtol(value, &end, 10);
    if (errno || *end || number < 3 || number > INT_MAX) return 2;
    int fd = static_cast<int>(number);

    char byte;
    ssize_t count;
    do {
        count = pread(fd, &byte, 1, 0);
    } while (count < 0 && errno == EINTR);
    int closed = close(fd);
    return count == 1 && byte == 'W' && closed == 0 ? 0 : 1;
}
