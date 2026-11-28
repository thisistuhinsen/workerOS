#define _POSIX_C_SOURCE 200809L
#include <workeros/input.h>
#include <array>
#include <cstdlib>

int main(int argc, char **argv)
{
    workeros_input input = WORKEROS_INPUT_INIT;
    if (argc == 2) {
        const auto original = std::atoi(argv[1]);
        const auto refusal = workeros_open_inherited("INPUT", WORKEROS_OWNED, &input);
        return refusal == -1 && input.fd == -1 && fcntl(original, F_GETFD) >= 0 ? 0 : 1;
    }

    if (workeros_open_inherited("INPUT", WORKEROS_OWNED, &input) == -1) {
        return 2;
    }
    const auto fd = input.fd;
    std::array<char, 2> bytes{};
    if (lseek(fd, 0, SEEK_CUR) != 2
        || workeros_read_at(&input, bytes.data(), bytes.size(), 1) != 2
        || bytes != std::array<char, 2>{ 'o', 'r' } || lseek(fd, 0, SEEK_CUR) != 2) {
        return 3;
    }
    if (workeros_read_at(&input, bytes.data(), bytes.size(), -1) != -1 || errno != EINVAL) {
        return 4;
    }
    if (workeros_close(&input) == -1 || workeros_close(&input) == -1) {
        return 5;
    }
    return fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 6;
}
