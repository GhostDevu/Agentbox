/* Probe SYSCALL (seccomp): is the dangerous syscall surface filtered?
 * ptrace(PTRACE_TRACEME) normally succeeds for a process. hardened installs a
 * seccomp-bpf filter that denies ptrace (and bpf, mount, setns, ... ) with
 * EPERM -> CONTAINED. weak installs no filter -> ptrace succeeds -> CROSSED.
 * ptrace is a good canary: it is the primary anti-debug / escalation primitive
 * we want a hostile target to be denied. Benign: traces nothing. */
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
