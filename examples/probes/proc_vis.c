/* Probe PID namespace: a new namespace makes the target pid 1 (CONTAINED); a
 * shared host namespace gives an ordinary pid (CROSSED). getpid() needs no /proc. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    pid_t me = getpid();
    if (me == 1)
        printf("CONTAINED: PID namespace isolated (I am init, pid 1)\n");
    else
        printf("CROSSED: shared PID namespace (my pid is %d, not 1)\n", (int)me);
    return 0;
}
