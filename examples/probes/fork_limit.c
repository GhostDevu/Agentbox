/* Probe PROCESS-LIMIT (fork containment): how many processes can the target
 * create? hardened caps it via RLIMIT_NPROC / cgroup pids.max -> only a few
 * succeed (CONTAINED). weak applies no limit -> many succeed (CROSSED).
 *
 * BENIGN and BOUNDED: it attempts at most MAX children, each sleeps briefly and
 * exits, and the parent kills/reaps them. This is NOT a real fork bomb. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX 250
#define THRESHOLD 150 /* >= this many => effectively unlimited => CROSSED */

int main(void) {
    pid_t kids[MAX];
    int n = 0;
    for (; n < MAX; n++) {
        pid_t p = fork();
        if (p < 0) break;      /* hit the limit */
        if (p == 0) { sleep(2); _exit(0); } /* child */
        kids[n] = p;
    }
    for (int i = 0; i < n; i++) kill(kids[i], SIGKILL);
    for (int i = 0; i < n; i++) waitpid(kids[i], NULL, 0);

    if (n >= THRESHOLD)
        printf("CROSSED: created %d processes (no fork limit)\n", n);
    else
        printf("CONTAINED: fork limited to %d processes\n", n);
    return 0;
}
