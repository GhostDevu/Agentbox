/* Probe host-file read: /etc/hostname is absent in the pivoted rootfs
 * (CONTAINED) but visible when the host FS is shared (CROSSED). Benign: reads only. */
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
