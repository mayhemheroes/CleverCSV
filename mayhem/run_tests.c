#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#ifndef PYTHON
#define PYTHON "/mayhem/test-venv/bin/python3"
#endif

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    char *args[] = {
        (char *)PYTHON,
        (char *)"-m",
        (char *)"unittest",
        (char *)"discover",
        (char *)"-s",
        (char *)"tests/test_unit",
        (char *)"-v",
        NULL
    };
    execvp(PYTHON, args);
    perror("execvp " PYTHON);
    return 127;
}
