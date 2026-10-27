/* A benign but buggy target: a NULL-pointer write that faults with SIGSEGV.
 * Under the gdb tracer this yields a backtrace pointing at `clobber`, which is
 * the kind of crash-localization signal ARCTIC wants. Safe: it only crashes
 * itself. */
#include <stdio.h>

static void clobber(int depth) {
    if (depth > 0) {
        clobber(depth - 1);
        return;
    }
    int *p = NULL;
    *p = 42;              /* <-- the bug: NULL dereference */
}

int main(void) {
    printf("about to crash\n");
    clobber(3);
    printf("never reached\n");
    return 0;
}
