/* Probe root-FS write: read-only root fails (CONTAINED), writable root succeeds
 * (CROSSED). Benign: removes the file it creates. */
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
