/* Probe fork containment: hardened caps processes (CONTAINED), weak doesn't
 * (CROSSED). Benign and bounded: at most MAX short-lived children, all reaped. */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX 250
#define THRESHOLD 150 /* >= this many => effectively unlimited */

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
