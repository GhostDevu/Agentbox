/* Canary probe C-1: can the target read a host file?
 * Tries to open /etc/hostname (a host path). On the hardened sandbox the root
 * is a clean pivoted rootfs, so this file does not exist -> CONTAINED. On the
 * weak policy the host FS is visible -> CROSSED. Benign: it only reads. */
#include <stdio.h>

int main(void) {
    FILE *f = fopen("/etc/hostname", "r");
    if (!f) {
        printf("CONTAINED: cannot open /etc/hostname (host FS not visible)\n");
        return 0;
    }
    char buf[256] = {0};
    if (fgets(buf, sizeof buf, f)) printf("CROSSED: read host /etc/hostname: %s", buf);
    else printf("CROSSED: opened /etc/hostname (empty)\n");
    fclose(f);
    return 0;
}
