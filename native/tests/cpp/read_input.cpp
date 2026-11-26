#define _POSIX_C_SOURCE 200809L
#include <worker_handoff/input.h>
#include <array>
#include <cstdlib>

int main(int argc, char **argv)
{
    worker_handoff_input input = WORKER_HANDOFF_INPUT_INIT;
    if (argc == 2) {
        const auto original = std::atoi(argv[1]);
        const auto refusal = worker_handoff_open_inherited("INPUT", WORKER_HANDOFF_OWNED, &input);
        return refusal == -1 && input.fd == -1 && fcntl(original, F_GETFD) >= 0 ? 0 : 1;
    }

    if (worker_handoff_open_inherited("INPUT", WORKER_HANDOFF_OWNED, &input) == -1) {
        return 2;
    }
    const auto fd = input.fd;
    std::array<char, 2> bytes{};
    if (lseek(fd, 0, SEEK_CUR) != 2
        || worker_handoff_read_at(&input, bytes.data(), bytes.size(), 1) != 2
        || bytes != std::array<char, 2>{ 'o', 'r' } || lseek(fd, 0, SEEK_CUR) != 2) {
        return 3;
    }
    if (worker_handoff_read_at(&input, bytes.data(), bytes.size(), -1) != -1 || errno != EINVAL) {
        return 4;
    }
    if (worker_handoff_close(&input) == -1 || worker_handoff_close(&input) == -1) {
        return 5;
    }
    return fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 6;
}
