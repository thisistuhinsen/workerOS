#define _POSIX_C_SOURCE 200809L
#include <workeros/input.h>

int main(int argc, char **argv)
{
    workeros_input input = WORKEROS_INPUT_INIT;
    if (argc == 2) {
        int original = atoi(argv[1]);
        int refusal = workeros_open_inherited("INPUT", WORKEROS_OWNED, &input);
        return refusal == -1 && input.fd == -1 && fcntl(original, F_GETFD) >= 0 ? 0 : 1;
    }

    if (workeros_open_inherited("INPUT", WORKEROS_BORROWED, &input) == -1) {
        return 2;
    }
    const int fd = input.fd;
    char byte = '\0';
    if (lseek(fd, 0, SEEK_CUR) != 2 || workeros_read_at(&input, &byte, 1, 0) != 1
        || byte != 'W' || lseek(fd, 0, SEEK_CUR) != 2) {
        return 3;
    }
    if (workeros_close(&input) == -1 || fcntl(fd, F_GETFD) == -1
        || workeros_read_at(&input, &byte, 1, 0) != -1 || errno != EBADF) {
        return 4;
    }
    if (workeros_open_inherited("INPUT", WORKEROS_OWNED, &input) == -1
        || workeros_read_at(&input, &byte, 1, 100) != 0
        || workeros_close(&input) == -1 || workeros_close(&input) == -1) {
        return 5;
    }
    return fcntl(fd, F_GETFD) == -1 && errno == EBADF ? 0 : 6;
}
