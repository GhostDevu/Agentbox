/* Probe seccomp: the hardened filter denies ptrace with EPERM (CONTAINED); with
 * no filter ptrace(PTRACE_TRACEME) succeeds (CROSSED). Benign: traces nothing. */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

int main(void) {
    errno = 0;
    long r = ptrace(PTRACE_TRACEME, 0, 0, 0);
    if (r == 0)
        printf("CROSSED: ptrace(PTRACE_TRACEME) allowed (no seccomp filter)\n");
    else
        printf("CONTAINED: ptrace blocked (%s)\n", strerror(errno));
    return 0;
}
