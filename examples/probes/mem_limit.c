/* Probe MEMORY (limit containment): how much memory can the target allocate?
 * hardened caps it via RLIMIT_AS (and best-effort cgroup memory.max) -> an
 * allocation well below the cap fails (CONTAINED). weak applies no limit -> the
 * allocation reaches the ceiling (CROSSED).
 *
 * BENIGN and BOUNDED: it allocates and touches at most MAX_MB in CHUNK_MB steps
 * and stops as soon as an allocation fails. With RLIMIT_AS the failing malloc
 * returns NULL cleanly; with cgroup memory.max the process may instead be
 * OOM-killed, which the sandbox reports as a kill signal. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHUNK_MB 64
#define MAX_MB 1024
#define THRESHOLD_MB 1024 /* reaching this => effectively unlimited => CROSSED */

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
