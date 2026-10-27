/* A benign canary: writes to stdout and makes a couple of syscalls to trace. */
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    printf("hello from agentbox target (argc=%d)\n", argc);
    for (int i = 1; i < argc; i++) {
        printf("  arg[%d] = %s\n", i, argv[i]);
    }
    write(STDOUT_FILENO, "done\n", 5);
    return 0;
}
