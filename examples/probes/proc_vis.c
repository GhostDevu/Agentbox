/* Probe PROCESS: is the target in an isolated PID namespace?
 * In a new PID namespace the target execs as PID 1 (the namespace init), so it
 * cannot see or signal host/container processes -> CONTAINED. When the host PID
 * namespace is shared (weak), the target gets an ordinary high PID and host
 * processes are visible -> CROSSED. getpid() is a robust discriminator that
 * does not depend on /proc being mounted. */
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
