/* A fixed disposable effect on the already appointed stdout original. */
#include <stdio.h>

int main(void) {
    if (fputs("worker ready\n", stdout) == EOF || fflush(stdout) == EOF) {
        return 1;
    }
    return 0;
}
