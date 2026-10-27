/* Probe memory limit: hardened caps allocation (CONTAINED), weak doesn't
 * (CROSSED). Benign and bounded: touches at most MAX_MB, stops at the first
 * failure (RLIMIT_AS returns NULL; cgroup memory.max may OOM-kill instead). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK_MB 64
#define MAX_MB 1024
#define THRESHOLD_MB 1024 /* reaching this => effectively unlimited */

int main(void) {
    size_t chunk = (size_t)CHUNK_MB * 1024 * 1024;
    int got_mb = 0;
    for (int i = 0; i < MAX_MB / CHUNK_MB; i++) {
        char *p = malloc(chunk);
        if (!p) break;
        memset(p, 1, chunk); /* fault it in so RSS actually grows */
        got_mb += CHUNK_MB;
    }
    if (got_mb >= THRESHOLD_MB)
        printf("CROSSED: allocated %d MB (no memory limit)\n", got_mb);
    else
        printf("CONTAINED: memory limited; allocation failed after %d MB\n", got_mb);
    return 0;
}
