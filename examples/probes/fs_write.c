/* Probe FS-WRITE: can the target write to the root filesystem?
 * hardened remounts / read-only -> write fails (CONTAINED). weak keeps a
 * writable host-root view -> write succeeds (CROSSED). Benign: removes the file
 * it creates. */
#include <stdio.h>
#include <unistd.h>

int main(void) {
    const char *path = "/abx_write_test";
    FILE *f = fopen(path, "w");
    if (!f) {
        printf("CONTAINED: cannot write to / (read-only root)\n");
        return 0;
    }
    fputs("x", f);
    fclose(f);
    unlink(path);
    printf("CROSSED: wrote %s (root is writable)\n", path);
    return 0;
}
