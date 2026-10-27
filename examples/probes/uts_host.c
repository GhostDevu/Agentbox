/* Probe UTS: is the target in an isolated UTS namespace?
 * hardened gives a new UTS namespace with hostname "agentbox" (and the target
 * cannot change the host's hostname) -> CONTAINED. weak shares the host UTS
 * namespace, so the hostname is the host's -> CROSSED. Benign: read-only. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char host[256] = {0};
    if (gethostname(host, sizeof host - 1) != 0) {
        printf("CONTAINED: gethostname failed\n");
        return 0;
    }
    if (strcmp(host, "agentbox") == 0)
        printf("CONTAINED: UTS namespace isolated (hostname=%s)\n", host);
    else
        printf("CROSSED: shared UTS namespace (hostname=%s)\n", host);
    return 0;
}
